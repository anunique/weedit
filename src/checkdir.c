#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS_64

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "../include/structs.h"
#include "../include/error.h"
#include "../include/crc32.h"
#include "../include/sha1.h"

void checkdir(weedit_db *db, char *cwd)
{
	DIR *dir;
	FILE *hFile;
	size_t tmpsize;
	dlink_dnode *dnode, *dnode2;
	dlink_fnode *fnode, *fnode2;
	SHA1_CTX sha1;
	u_int8_t dupe;
	char tmp[5000];
	u_int16_t entryptr, entryptr2;
	u_int32_t value, value2;
	u_int64_t fsize, fsize2;
	struct dirent *de;
	struct stat64 stat_buf, stat_buf2;
	dlink_dlist *checksum = &db->checksum;
	dlink_flist *fname = &db->fname;
	dlink_dnode **checksumptr = db->checksumptr;
	dlink_fnode **fnameptr = db->fnameptr;

	dir = fdopendir(open(cwd, O_RDONLY));
	if (NULL == dir)
	{
		if (!quiet)
			myerror(0, "Error: unable to opendir('%s')\n", cwd);
		return;
	}
_readdir:
	de = readdir(dir);
	if (!de)
	{
		closedir(dir);
		return;
	}
	snprintf(tmp, sizeof(tmp), "%s/%s", cwd, de->d_name);
	if (lstat64(tmp, &stat_buf))
		goto _readdir;
	if (S_ISLNK(stat_buf.st_mode))
		goto _readdir;
	if (S_ISDIR(stat_buf.st_mode))
	{
		if (strcmp(de->d_name, "..") && strcmp(de->d_name, "."))
			checkdir(db, tmp);
		goto _readdir;
	}
	if (!S_ISREG(stat_buf.st_mode))
		goto _readdir;
	if (stat_buf.st_size == 0)
		goto _readdir;
	tmpsize = strlen(tmp) + 1;
	value = crc32(0xffffffff, (u_int8_t *)&tmp, tmpsize) ^ 0xffffffff;
	entryptr = (value & 0xffff0000) >> 16;
	entryptr2 = entryptr;
	while (!fnameptr[entryptr2])
		entryptr2--;
	fnode2 = fnameptr[entryptr2];
_fnodes:
	if (!fnode2)
	{
		fnode = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
		if (!fnode)
			myerror(-1, "Fatal: out of memory");
		fnode->prev = fname->tail;
		fnode->prev->next = fnode;
		fname->tail = fnode;
		if (!fnameptr[entryptr])
			fnameptr[entryptr] = fnode;
		goto _newfile;
	}
	value2 = fnode2->data->fnamecrc;
	if (value < value2)
	{
		fnode = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
		if (!fnode)
			myerror(-1, "Fatal: out of memory");
		if ((fnode2 == fnameptr[entryptr]) || !fnameptr[entryptr])
			fnameptr[entryptr] = fnode;
		if (fnode2 == fname->head)
		{
			fnode->next = fname->head;
			fnode->next->prev = fnode;
			fname->head = fnode;
			fnameptr[0] = fnode;
		}
		else
		{
			if (fnode2->prev)
				fnode2->prev->next = fnode;
			fnode->next = fnode2;
			fnode->prev = fnode2->prev;
			fnode2->prev = fnode;
		}
		goto _newfile;
	}
	if (value == value2)
	{
		dnode = fnode2->data;
		if (!strcmp(dnode->fname, tmp))
		{
			fnode = fnode2;
			if (dnode->mtime != stat_buf.st_mtime)
				goto _dataonly;
			if (dnode->ctime != stat_buf.st_ctime)
				goto _dataonly;
			if (dnode->fsize != stat_buf.st_size)
				goto _dataonly;
			goto _readdir;
		}
	}
	fnode2 = fnode2->next;
	goto _fnodes;
_dataonly:
	if (!quiet)
		printf("'%s' got modified - updating db entry - no scan for dupe in list done!\n", dnode->fname);
	dnode->fnamelen = 0;
_newfile:
	dnode = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + tmpsize + 1);
	if (!dnode)
		myerror(-1, "Fatal: out of memory");
	fnode->data = dnode;
	dnode->ctime = stat_buf.st_ctime;
	dnode->mtime = stat_buf.st_mtime;
	dnode->fsize = stat_buf.st_size;
	dnode->fnamecrc = value;
	dnode->fnamelen = tmpsize & 0xffff;
	memcpy(&dnode->fname, &tmp, tmpsize);
	hFile = fopen64(tmp, "rb");
	if (!hFile)
	{
		if (!quiet)
			myerror(0, "ERROR: unable to open '%s' (%s)\n", tmp, strerror(errno));
		goto _readdir;
	}
	fsize = stat_buf.st_size;
	fsize2 = fsize;
	if (fsize2 > CHUNK_SIZE)
		fsize2 = CHUNK_SIZE;
	if (!fread(buf, fsize2, 1, hFile))
	{
		if (!quiet)
			myerror(0, "ERROR: unable to read '%s'\n", tmp);
		fclose(hFile);
		goto _readdir;
	}
	fsize -= fsize2;
	SHA1_Init(&sha1);
	dnode->crc32 = crc32(0xffffffff, buf, fsize2) ^ 0xffffffff;
	SHA1_Update(&sha1, buf, fsize2);
	entryptr = (dnode->crc32 & 0xffff0000) >> 16;
	entryptr2 = entryptr;
	while (!checksumptr[entryptr2])
		entryptr2--;
	dnode2 = checksumptr[entryptr2];
	if (!fsize)
	{
		SHA1_Final(&sha1, dnode->sha1);
	}
	dupe = 0;
_dnodes:
	if (!dnode2)
	{
		dnode->prev = checksum->tail;
		dnode->prev->next = dnode;
		checksum->tail = dnode;
		if (!checksumptr[entryptr])
			checksumptr[entryptr] = dnode;
		if (forcescan)
		{
			if (fsize)
			{
				while (fsize)
				{
					fsize2 = fsize;
					if (fsize2 > CHUNK_SIZE)
						fsize2 = CHUNK_SIZE;
					if (!fread(buf, fsize2, 1, hFile))
						myerror(-1, "Fatal: fread error that shouldnt happen!");
					SHA1_Update(&sha1, buf, fsize2);
					fsize -= fsize2;
				}
				SHA1_Final(&sha1, dnode->sha1);
				bytes += dnode->fsize;
				bytes2 += dnode->fsize;
				fclose(hFile);
				hFile = 0;
			}
		}
		else
		{
			bytes += fsize2;
			bytes2 += dnode->fsize;
			if (hFile)
				fclose(hFile);
		}
		goto _readdir;
	}
	if (dnode->crc32 < dnode2->crc32)
	{
		if ((dnode2 == checksumptr[entryptr]) || !checksumptr[entryptr])
			checksumptr[entryptr] = dnode;
		if (dnode2 == checksum->head)
		{
			dnode->next = checksum->head;
			dnode->prev = 0;
			dnode->next->prev = dnode;
			checksum->head = dnode;
			checksumptr[0] = dnode;
		}
		else
		{
			if (dnode2->prev)
				dnode2->prev->next = dnode;
			dnode->next = dnode2;
			dnode->prev = dnode2->prev;
			dnode2->prev = dnode;
		}
		if (forcescan)
		{
			if (fsize)
			{
				while (fsize)
				{
					fsize2 = fsize;
					if (fsize2 > CHUNK_SIZE)
						fsize2 = CHUNK_SIZE;
					if (!fread(buf, fsize2, 1, hFile))
						myerror(-1, "Fatal: fread error that shouldnt happen!");
					SHA1_Update(&sha1, buf, fsize2);
					fsize -= fsize2;
				}
				SHA1_Final(&sha1, dnode->sha1);
				bytes += dnode->fsize;
				bytes2 += dnode->fsize;
				fclose(hFile);
				hFile = 0;
			}
		}
		else
		{
			bytes += fsize2;
			bytes2 += dnode->fsize;
			if (hFile)
				fclose(hFile);
		}
		goto _readdir;
	}
	if (forcescan)
		goto _forcescan;
	if (dnode->fsize != dnode2->fsize)
	{
		dnode2 = dnode2->next;
		goto _dnodes;
	}
	if (dnode->crc32 != dnode2->crc32)
	{
		dnode2 = dnode2->next;
		goto _dnodes;
	}
_forcescan:
	if (fsize)
	{
		while (fsize)
		{
			fsize2 = fsize;
			if (fsize2 > CHUNK_SIZE)
				fsize2 = CHUNK_SIZE;
			if (!fread(buf, fsize2, 1, hFile))
				myerror(-1, "Fatal: fread error that shouldnt happen!");
			SHA1_Update(&sha1, buf, fsize2);
			fsize -= fsize2;
		}
		SHA1_Final(&sha1, dnode->sha1);
		bytes += dnode->fsize;
		bytes2 += dnode->fsize;
		fclose(hFile);
		hFile = 0;
	}
	if (0 == memcmp(dnode2->sha1, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20))
	{
		hFile = fopen64(dnode2->fname, "rb");
		if (!hFile)
		{
			dnode2 = dnode2->next;
			goto _dnodes;
		}
		fsize = dnode2->fsize;
		SHA1_Init(&sha1);
		while (fsize)
		{
			fsize2 = fsize;
			if (fsize2 > CHUNK_SIZE)
				fsize2 = CHUNK_SIZE;
			if (!fread(buf, fsize2, 1, hFile))
			{
				if (!quiet)
					myerror(0, "ERROR: unable to read '%s'\n", dnode2->fname);
				fclose(hFile);
				hFile = 0;
				dnode2 = dnode2->next;
				goto _dnodes;
			}
			SHA1_Update(&sha1, buf, fsize2);
			fsize -= fsize2;
		}
		SHA1_Final(&sha1, dnode2->sha1);
		bytes += dnode2->fsize;
		bytes2 += dnode2->fsize;
	}
	if (!dnode2->fnamelen)
	{
		dnode2 = dnode2->next;
		goto _dnodes;
	}
	if (memcmp(dnode->sha1, dnode2->sha1, 20))
	{
		dnode2 = dnode2->next;
		goto _dnodes;
	}
	if (lstat64(dnode2->fname, &stat_buf2))
	{
		if (!quiet)
			printf("'%s' is gone - DELETING OUT OF DB\n", dnode2->fname);
		dnode2->fnamelen = 0;
		dnode2 = dnode2->next;
		goto _dnodes;
	}
	if ((dnode2->ctime != stat_buf2.st_ctime) || (dnode2->mtime != stat_buf2.st_mtime) || (dnode2->fsize != stat_buf2.st_size))
	{
		if (!quiet)
			printf("'%s' got modified - DELETING OUT OF DB, RESCAN TO READD!\n", dnode2->fname);
		dnode2->fnamelen = 0;
		dnode2 = dnode2->next;
		goto _dnodes;
	}
	if (!dupe)
	{
		dupe = 1;
		dupes++;
		if (deldupes)
		{
			if (!unlink(dnode->fname))
			{
				dnode->fnamelen = 0;
				if (!quiet)
					printf("'%s' IS a DUPE with '%s' - DELETED\n", dnode->fname, dnode2->fname);
				if (hFile)
					fclose(hFile);
				hFile = 0;
				goto _readdir;
			}
			else if (!quiet)
				printf("'%s' IS a DUPE with '%s' - unable to delete!!!\n", dnode->fname, dnode2->fname);
		}
		else if (!quiet)
			printf("'%s' IS a DUPE with '%s'\n", dnode->fname, dnode2->fname);
	}
	if (hFile)
		fclose(hFile);
	hFile = 0;
	dnode2 = dnode2->next;
	goto _dnodes;
}
