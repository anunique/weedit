// bla here i go with the code
// no i wont add comments - CW
// before you even think about bitching, the kernel will free any unused memory on exit! no need to bother about cleaning up.
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
#include "../include/scandb.h"

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
	char *dbname1 = 0, *dbname2 = 0;
	unsigned char truncatedb = 0, noadd = 0, deldupesfromdb = 0, printdb = 0, comparedb = 0;
	char *dir_to_scan = 0;
	u_int64_t files = 0;
	float timeval;
	struct timeval timer1, timer2;
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
					dbname1 = argv[paramn++];
				if (paramn == argc)
					usage(argv[0]);
				else
					dbname2 = argv[paramn++];
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
			printf("Compare '%s' with '%s' and print missing files\nFiles Missing in '%s':\n", dbname1, dbname2, dbname1);
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
	weedit_db *db1;
	db1 = calloc(1, sizeof(weedit_db));
	if (db1 == 0)
	{
		myerror(-1, "FATAL: out of memory");
	}
	gettimeofday(&timer1, 0);
	if (comparedb)
	{
		comparedbs(dbname1, dbname2);
	}
	else
	{
		dupes = 0;
		bytes = 0;
		bytes2 = 0;
		if (!truncatedb)
		{
			void *error = load_db(db1, load);
			if (error)
				myerror(-1, error);
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
			checkdir(db1, tmp);
			chdir(home);
		}
		if (deldupesfromdb)
		{
			scandb(db1);
		}
		if (printdb)
		{
			if (!quiet)
				printf("CHUNKID  | CRC32    | Filesize         | SHA1                                     | StatusChangeTime | ModificationTime | Filename\n");
			for (int i = 0; i < TABLE_SIZE; i++)
			{
				dlink_dnode *dnode = db1->checksumptr[i];
				while (dnode)
				{
					if (dnode->fnamelen)
					{
						printf("%08X | ", dnode->chunkcrc32);
						printf("%08X | ", dnode->crc32);
						printf("%016" PRIx64 " | ", dnode->fsize);
						for (int j = 0; j < 20; j++)
							printf("%02X", dnode->sha1[j]);
						printf(" | ");
						printf("%016" PRIx64 " | ", dnode->ctime);
						printf("%016" PRIx64 " | ", dnode->mtime);
						printf("%s\n", dnode->fname);
					}
					dnode = dnode->next;
				}
			}
		}
		files = 0;
		for (int i = 0; i < TABLE_SIZE; i++)
		{
			dlink_dnode *dnode = db1->checksumptr[i];
			while (dnode)
			{
				if (dnode->fnamelen)
					files++;
				dnode = dnode->next;
			}
		}
		if (!noadd)
		{
			void *error = save_db(db1, save);
			if (error)
				myerror(-1, error);
		}
	}
	if (!quiet)
	{
		gettimeofday(&timer2, 0);
		timeval = (float)(timer2.tv_sec - timer1.tv_sec) + ((float)(timer2.tv_usec - timer1.tv_usec) / 1000000);
		printf("\n\n%" PRIu64 " bytes read - %" PRIu64 " bytes in filesize scanned - %" PRIu64 " entries - %" PRIu64 " dupes - needed time: %f seconds\n", bytes, bytes2, files, dupes, timeval);
		printf("Scanspeed: %f MB per second\n", (float)bytes / timeval / 1000000);
	}
	return 0;
}
