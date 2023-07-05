// bla here i go with the code
// no i wont add comments - CW
// TODO: scan for TODO

char *ver = "\nWeedIt 4.0.0-dev by daniel (at) k0o (dot) org\n";
char *id = "\n\n\n\n\n-CW was here-\n\n\n\n";

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
#include "../include/io.h"
#include "../include/crc32.h"
#include "../include/sha1.h"
#include "../include/comparedbs.h"
#include "../include/error.h"

u_int8_t quiet, deldupes, forcescan;
u_int8_t *buf;
u_int64_t bytes, bytes2, dupes;

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

void usage(char *fname)
{
	printf("USAGE: %s -cdflnpqstuv [[DB1] [DB2]] [db to load] [db to save] [directory to scan]\n", fname);
	printf("\tc [DB1] [DB2]= compare DB1 with DB2\n");
	printf("\td = scan for dupes saved in DB\n");
	printf("\tf = force weedit to calculate sha1\n");
	printf("\tl [DB] = load name given\n");
	printf("\tn = dont add files to db (dont save it)\n");
	printf("\tp = print database\n");
	printf("\tq = quiet mode\n");
	printf("\ts [DB] = save name given (else save name = load name)\n");
	printf("\tt = truncate database (dont load it)\n");
	printf("\tu = unlink (delete) new dupes\n");
	printf("\tv = show version information\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	char home[5000];
	char tmp[5000];
	char *paramv;
	int paramn;
	char *load = 0, *save = 0;
	char *db1 = 0, *db2 = 0;
	u_int8_t truncatedb = 0, noadd = 0, deldupesfromdb = 0, printdb = 0, comparedb = 0;
	char *dir_to_scan = 0;
	u_int32_t i;
	u_int64_t files;
	float timeval;
	struct timeval timer1, timer2;
	dlink_dnode *dnode, *dnode2;
	dlink_fnode *fnode;
	dlink_dlist *checksum;
	dlink_flist *fname;
	if (argc < 2)
		usage(argv[0]);
	quiet = 0;
	deldupes = 0;
	forcescan = 0;
	paramn = 1;
	paramv = argv[paramn];
	if (*paramv == '-')
	{
		paramn++;
		while (*++paramv)
		{
			switch (*paramv)
			{
			case 'c':
				comparedb = 1;
				if (paramn == argc)
					usage(argv[0]);
				else
					db1 = argv[paramn++];
				if (paramn == argc)
					usage(argv[0]);
				else
					db2 = argv[paramn++];
				break;
			case 'd':
				deldupesfromdb = 1;
				break;
			case 'f':
				forcescan = 1;
				break;
			case 'l':
				if (paramn == argc)
					usage(argv[0]);
				else
					load = argv[paramn++];
				break;
			case 'n':
				noadd = 1;
				break;
			case 'p':
				printdb = 1;
				break;
			case 'q':
				quiet = 1;
				break;
			case 's':
				if (paramn == argc)
					usage(argv[0]);
				else
					save = argv[paramn++];
				break;
			case 't':
				truncatedb = 1;
				break;
			case 'u':
				deldupes = 1;
				break;
			case 'v':
				printf("Version: %s", ver);
				break;
			default:
				usage(argv[0]);
			}
		}
	}
	if (paramn < argc)
		dir_to_scan = argv[paramn];
	if ((paramn == argc) && !deldupesfromdb && !printdb && !comparedb)
		usage(argv[0]);
	if (!load)
		load = "weedit.dat";
	if (!save)
		save = load;
	if (deldupesfromdb)
		truncatedb = 0;
	if (printdb)
	{
		truncatedb = 0;
	}
	if (!quiet)
	{
		printf("%s settings:\n", argv[0]);
		if (comparedb)
		{
			printf("Compare '%s' with '%s' and print missing files\nFiles Missing in '%s':\n", db1, db2, db1);
		}
		else
		{
			printf("Load DB               : %s\n", load);
			printf("Save DB as            : %s\n", save);
			if (dir_to_scan)
				printf("Directory to scan     : %s\n", dir_to_scan);
			if (deldupesfromdb)
			{
				printf("Delete dupes from DB   : YES\n");
			}
			else
			{
				printf("Delete dupes from DB  : NO\n");
			}
			if (truncatedb)
				printf("Truncate DB           : YES\n");
			else
				printf("Truncate DB           : NO\n");
			if (deldupes)
				printf("Delete new dupes      : YES\n");
			else
				printf("Delete new dupes      : NO\n");
			if (forcescan)
				printf("Force filescan        : YES\n");
			else
				printf("Force filescan        : NO\n");
			if (printdb)
				printf("Print DB              : YES\n");
			else
				printf("Print DB              : NO\n");
			if (noadd)
				printf("Save DB               : NO\n");
			else
				printf("Save DB               : YES\n");
			printf("Be quiet              : NO\n-----------------------------------------------\nDUPE List:\n");
		}
	}

	weedit_db *weedit_db1;
	weedit_db1 = calloc(1, sizeof(weedit_db));
	if (weedit_db1 == 0)
	{
		myerror(-1, "FATAL: out of memory");
	}

	dlink_dnode **checksumptr = weedit_db1->checksumptr;
	dlink_fnode **fnameptr = weedit_db1->fnameptr;

	gettimeofday(&timer1, 0);

	if (comparedb) 
	{
		comparedbs(db1, db2);
	}
	else
	{
		fname = &weedit_db1->fname;
		checksum = &weedit_db1->checksum;
		dupes = 0;
		bytes = 0;
		bytes2 = 0;
		if (!truncatedb)
		{
			void *error = load_db(weedit_db1, load);
			if (error)
				myerror(-1, error);
		}
		if (!fname->head)
		{
			fnode = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
			if (!fnode)
				myerror(-1, "Fatal: out of memory");
			dnode = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + 1);
			if (!dnode)
				myerror(-1, "Fatal: out of memory");
			fnode->data = dnode;
			fname->head = fnode;
			fname->tail = fnode;
			fnameptr[0] = fnode;
			checksum->head = dnode;
			checksum->tail = dnode;
			checksumptr[0] = dnode;
		}
		if (dir_to_scan)
		{
			if (!(buf = (u_int8_t *)malloc(CHUNK_SIZE)))
			{
				myerror(0, "ERROR: Unable to allocate memory\n");
				exit(-1);
			}
			getcwd(home, sizeof(home));
			if (chdir(dir_to_scan))
			{
				myerror(0, "ERROR: Directory '%s' not found!!!\n", dir_to_scan);
				exit(-1);
			}
			getcwd(tmp, sizeof(tmp));
			checkdir(weedit_db1, tmp);
			chdir(home);
		}
		if (deldupesfromdb)
		{
			dnode = checksum->head;
		_deldupes1:
			if (!dnode)
				goto _deldupesdone;
			if (!dnode->fnamelen)
			{
				dnode = dnode->next;
				goto _deldupes1;
			}
			dnode2 = dnode->next;
			goto _deldupes2;
		_deldupes2:
			if (!dnode2)
				goto _deldupesdone;
			if (!dnode2->fnamelen)
			{
				dnode2 = dnode2->next;
				goto _deldupes2;
			}
			if (dnode->crc32 != dnode2->crc32)
			{
				dnode = dnode2->next;
				goto _deldupes1;
			}
			if (dnode->fsize != dnode2->fsize)
			{
				dnode = dnode2->next;
				goto _deldupes1;
			}
			if (memcmp(dnode->sha1, dnode2->sha1, 20))
			{
				dnode = dnode2->next;
				goto _deldupes1;
			}
			// need a better way to do it. still better than v2.0.x!
			dupes++;
			if (deldupes)
			{
				if (!unlink(dnode2->fname))
				{
					dnode->fnamelen = 0;
					if (!quiet)
						printf("'%s' IS a DUPE with '%s' - DELETED\n", dnode2->fname, dnode->fname);
				}
				else if (!quiet)
					printf("'%s' IS a DUPE with '%s' - unable to delete!!!\n", dnode2->fname, dnode->fname);
			}
			else if (!quiet)
				printf("'%s' IS a DUPE with '%s'\n", dnode2->fname, dnode->fname);
			dnode2 = dnode2->next;
			goto _deldupes2;
		_deldupesdone:;
		}
		if (printdb)
		{
			if (!quiet)
				printf("CHUNKID  | CRC32    | Filesize         | SHA1                                     | StatusChangeTime | ModificationTime | Filename\n");
			for (dlink_dnode *node = checksum->head; node != NULL; node = node->next)
				if (node->fnamelen)
				{
					printf("%08X | ", node->chunkid);
					printf("%08X | ", node->crc32);
					printf("%016"PRIx64" | ", node->fsize);
					for (i = 0; i < 20; i++)
						printf("%02X", node->sha1[i]);
					printf(" | ");
					printf("%016"PRIx64" | ", node->ctime);
					printf("%016"PRIx64" | ", node->mtime);
					printf("%s\n", node->fname);
				}
		}
		files = 0;
		for (dlink_dnode *node = checksum->head; node != NULL; node = node->next)
			if (node->fnamelen)
				files++;
		if (!noadd)
		{
			void *error = save_db(weedit_db1, save);
			if (error)
				myerror(-1, error);
		}
	}
	if (!quiet)
	{
		gettimeofday(&timer2, 0);
		timeval = (float)(timer2.tv_sec - timer1.tv_sec) + ((float)(timer2.tv_usec - timer1.tv_usec) / 1000000);
		printf("\n\n%"PRIu64" bytes scanned - %"PRIu64" bytes processed - %"PRIu64" entries - %"PRIu64" dupes - needed time: %f seconds\n", bytes, bytes2, files, dupes, timeval);
		printf("Scanspeed: %f MB per second\n", (float)bytes / timeval / 1000000);
	}
	return 0;
}
