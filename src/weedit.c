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
#include "../include/checkdir.h"

u_int8_t quiet, deldupes, forcescan;
u_int8_t *buf;
u_int64_t bytes, bytes2, dupes;

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
			printf("Delete dupes from DB  : %s\n", deldupesfromdb ? "YES" : "NO");
			printf("Truncate DB           : %s\n", truncatedb ? "YES" : "NO");
			printf("Delete new dupes      : %s\n", deldupes ? "YES" : "NO");
			printf("Force filescan        : %s\n", forcescan ? "YES" : "NO");
			printf("Print DB              : %s\n", printdb ? "YES" : "NO");
			printf("Save DB               : %s\n", noadd ? "NO" : "YES");
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
