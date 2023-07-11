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
	DIR *dir = fdopendir(open(cwd, O_RDONLY));
	if (NULL == dir)
	{
		if (!quiet)
			myerror(0, "Error: unable to opendir('%s')\n", cwd);
		return;
	}
_readdir:
	struct dirent *de = readdir(dir);
	if (!de)
	{
		closedir(dir);
		return;
	}
	char fname[5000];
	snprintf(fname, sizeof(fname), "%s/%s", cwd, de->d_name);
	struct stat stat_buf;
	if (lstat(fname, &stat_buf))
		goto _readdir;
	if (S_ISLNK(stat_buf.st_mode))
	{
		printf("LINK: %s\n", fname);
		goto _readdir;
	}
	if (S_ISDIR(stat_buf.st_mode))
	{
		if (strcmp(de->d_name, "..") && strcmp(de->d_name, "."))
			checkdir(db, fname);
		goto _readdir;
	}
	if (!S_ISREG(stat_buf.st_mode))
		goto _readdir;
	if (stat_buf.st_size == 0)
		goto _readdir;
	size_t fnamelen = strlen(fname) + 1;
	unsigned long fnamecrc = crc32(0xffffffff, (unsigned char *)&fname, fnamelen) ^ 0xffffffff;
	dlink_fnode *fnode_cur = db->fnameptr[fnamecrc & TABLE_MASK];
	dlink_fnode *fnode_old = 0;
	dlink_dnode *dnode_cur = 0;
	dlink_dnode *dnode_new = 0;
_find_file:
	if (!fnode_cur)
		goto _new_file;
	if (fnamecrc < fnode_cur->data->fnamecrc)
		goto _new_file;
	if (fnamecrc == fnode_cur->data->fnamecrc)
	{
		dlink_dnode *dnode = fnode_cur->data;
		if (0 == strcmp(dnode->fname, fname))
		{
			if ((dnode->mtime == stat_buf.st_mtime) &&
				(dnode->ctime == stat_buf.st_ctime) &&
				(dnode->fsize == stat_buf.st_size))
			{
				goto _readdir;
			}
			dnode_cur = dnode;
			goto _update_data;
		}
	}
	fnode_old = fnode_cur;
	fnode_cur = fnode_cur->next;
	goto _find_file;
_new_file:
	dlink_fnode *fnode_new = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
	if (!fnode_new)
		myerror(-1, "Fatal: out of memory");
	dnode_new = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + fnamelen + 1);
	if (!dnode_new)
		myerror(-1, "Fatal: out of memory");
	dnode_new->fnamecrc = fnamecrc;
	dnode_new->fnamelen = fnamelen;
	memcpy(&dnode_new->fname, &fname, fnamelen);
	fnode_new->data = dnode_new;
	if (fnode_old == 0)
	{
		db->fnameptr[fnamecrc & TABLE_MASK] = fnode_new;
		fnode_new->next = fnode_cur;
		if (fnode_cur)
			fnode_cur->prev = fnode_new;
	}
	else if (fnode_cur == 0)
	{
		fnode_old->next = fnode_new;
		fnode_new->prev = fnode_old;
	}
	else
	{
		fnode_new->next = fnode_cur;
		fnode_new->prev = fnode_old;
		fnode_old->next = fnode_new;
		fnode_cur->prev = fnode_new;
	}
_update_data:
	if (dnode_cur)
	{
		if (!quiet)
			printf("'%s' got modified - updating db entry\n", fname);
		if (!dnode_cur->prev)
		{
			db->checksumptr[dnode_cur->chunkcrc32 & TABLE_MASK] = dnode_cur->next;
			if (dnode_cur->next)
				dnode_cur->next->prev = 0;
			dnode_cur->next = 0;
		}
		else
		{
			if (dnode_cur->next)
				dnode_cur->next->prev = dnode_cur->prev;
			if (dnode_cur->prev)
				dnode_cur->prev->next = dnode_cur->next;
			dnode_cur->next = 0;
			dnode_cur->prev = 0;
		}
		dnode_cur->crc32 = 0;
		dnode_cur->chunkcrc32 = 0;
		memset(dnode_cur->sha1, 0, 20);
		dnode_new = dnode_cur;
		dnode_cur = 0;
	}
	dnode_new->ctime = stat_buf.st_ctime;
	dnode_new->mtime = stat_buf.st_mtime;
	dnode_new->fsize = stat_buf.st_size;
	bytes2 += dnode_new->fsize;
	FILE *hFile = fopen(fname, "rb");
	if (!hFile)
	{
		if (!quiet)
			myerror(0, "ERROR: unable to open '%s' (%s)\n", fname, strerror(errno));
		dnode_new->fnamelen = 0;
		goto _readdir;
	}
	size_t bytesread;
	bytesread = fread(buf, 1, CHUNK_SIZE, hFile);
	if (bytesread == 0)
	{
		if (!quiet)
			myerror(0, "ERROR: unable to read '%s'\n", fname);
		fclose(hFile);
		dnode_new->fnamelen = 0;
		goto _readdir;
	}
	bytes += bytesread;
	unsigned long chunkcrc32 = crc32(0xffffffff, buf, bytesread) ^ 0xffffffff;
	dnode_cur = db->checksumptr[chunkcrc32 & TABLE_MASK];
	if (feof(hFile))
	{
		SHA1_CTX sha1;
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, buf, bytesread);
		SHA1_Final(&sha1, dnode_new->sha1);
		dnode_new->crc32 = chunkcrc32;
		fclose(hFile);
		hFile = 0;
	}
	dlink_dnode *dnode_old = 0;
_find_dnode:
	if (!dnode_cur)
		goto _add_dnode;
	if (chunkcrc32 < dnode_cur->chunkcrc32)
		goto _add_dnode;
	if ((chunkcrc32 == dnode_cur->chunkcrc32) && (dnode_new->fsize == dnode_cur->fsize))
	{
		if (!memcmp(dnode_cur->sha1, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 24))
		{
			if (hFile)
			{
				SHA1_CTX sha1;
				SHA1_Init(&sha1);
				u_int32_t filecrc32 = 0xffffffff;
				while (bytesread != 0)
				{
					SHA1_Update(&sha1, buf, bytesread);
					filecrc32 = crc32(filecrc32, buf, bytesread);
					bytesread = fread(buf, 1, CHUNK_SIZE, hFile);
					bytes += bytesread;
				}
				SHA1_Final(&sha1, dnode_new->sha1);
				dnode_new->crc32 = filecrc32 ^ 0xffffffff;
				if (!feof(hFile))
				{
					myerror(0, "error reading file %s\n", fname);
				}
				fclose(hFile);
				hFile = 0;
			}
			FILE *hFile = fopen(dnode_cur->fname, "rb");
			if (!hFile)
			{
				if (!quiet)
					myerror(0, "ERROR: unable to open '%s' (%s)\n", fname, strerror(errno));
				dnode_cur->fnamelen = 0;
			}
			else 
			{
				SHA1_CTX sha1;
				SHA1_Init(&sha1);
				u_int32_t filecrc32 = 0xffffffff;
				while ((bytesread = fread(buf, 1, CHUNK_SIZE, hFile)) > 0)
				{
					SHA1_Update(&sha1, buf, bytesread);
					filecrc32 = crc32(filecrc32, buf, bytesread);
					bytes += bytesread;
					bytes2 += bytesread;
				}
				SHA1_Final(&sha1, dnode_cur->sha1);
				dnode_cur->crc32 = filecrc32 ^ 0xffffffff;
				if (!feof(hFile))
				{
					myerror(0, "error reading file %s\n", dnode_cur->fname);
				}
				fclose(hFile);
				hFile = 0;
			}
		}
		if (dnode_cur->fnamelen && (!memcmp(dnode_cur->sha1, dnode_new->sha1, 24)))
		{
			dupes++;
			if (deldupes)
			{
				if (!unlink(dnode_new->fname))
				{
					dnode_new->fnamelen = 0;
					if (!quiet)
						printf("'%s' IS a DUPE with '%s' - DELETED\n", dnode_new->fname, dnode_cur->fname);
					goto _readdir;
				}
				else if (!quiet)
					printf("'%s' IS a DUPE with '%s' - unable to delete!!!\n", dnode_new->fname, dnode_cur->fname);
			}
			else if (!quiet)
				printf("'%s' IS a DUPE with '%s'\n", dnode_new->fname, dnode_cur->fname);
		}
		goto _add_dnode;
	}
	dnode_old = dnode_cur;
	dnode_cur = dnode_cur->next;
	goto _find_dnode;
_add_dnode:
	if (hFile)
		fclose(hFile);
	dnode_new->chunkcrc32 = chunkcrc32;
	if (dnode_old == 0)
	{
		db->checksumptr[chunkcrc32 & TABLE_MASK] = dnode_new;
		dnode_new->next = dnode_cur;
		if (dnode_cur)
			dnode_cur->prev = dnode_new;
	}
	else if (dnode_cur == 0)
	{
		dnode_old->next = dnode_new;
		dnode_new->prev = dnode_old;
	}
	else
	{
		dnode_new->next = dnode_cur;
		dnode_new->prev = dnode_old;
		dnode_old->next = dnode_new;
		dnode_cur->prev = dnode_new;
	}
	goto _readdir;
}
