#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS_64

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "../include/structs.h"
#include "../include/comparedbs.h"
#include "../include/error.h"

//TODO: FIX THIS STUFF, JUST LOAD 2 DBS AND COMPARE EM, LETS NOT BOTHER FOR NOW
int comparedbs(char *db1, char *db2)
{
    dlink_dnode *dnode, *dnode2;
    FILE *hFile, *hFile2;
    char tmp[5000];
    u_int64_t i;
    u_int64_t files, files2;
    u_int32_t oldcrc32;
    u_int8_t comparedb = 1;

    dnode = (dlink_dnode *)calloc(1, CHUNK_SIZE);
    if (!dnode)
        myerror(-1, "FATAL: out of memory");
    dnode2 = (dlink_dnode *)calloc(1, CHUNK_SIZE);
    if (!dnode2)
        myerror(-1, "FATAL: out of memory");
    if (!(hFile = fopen(db1, "rb")))
        myerror(-1, "FATAL: unable to open db1!");
    if (!fread(tmp, 8, 1, hFile))
        myerror(-1, "FATAL: unable to open db!");
    if (memcmp(&tmp, "WEEDIT\4\0", 8))
        myerror(-1, "FATAL: db incompatible!");
    if (!fread(&i, 8, 1, hFile))
        myerror(-1, "FATAL: unable to open db!");
    if (i != 0x0102030405060708)
        myerror(-1, "FATAL: incompatible endian!");
    if (fgetc(hFile) != sizeof(void *))
        myerror(-1, "FATAL: sizeof(void *) incompatible!");
    if (fgetc(hFile) != sizeof(time_t))
        myerror(-1, "FATAL: sizeof(time_t) incompatible!");
    if (fgetc(hFile) != 'C')
        myerror(-1, "FATAL: db incompatible!");
    if (fgetc(hFile) != 'W')
        myerror(-1, "FATAL: db incompatible!");
    if (!fread(&files, sizeof(u_int64_t), 1, hFile))
        myerror(-1, "FATAL: unable to open db!");
    if (!(hFile2 = fopen(db2, "rb")))
        myerror(-1, "FATAL: unable to open db2!");
    if (!fread(tmp, 8, 1, hFile2))
        myerror(-1, "FATAL: unable to open db2!");
    if (memcmp(&tmp, "WEEDIT\4\0", 8))
        myerror(-1, "FATAL: db2 incompatible!");
    if (!fread(&i, 8, 1, hFile2))
        myerror(-1, "FATAL: unable to open db2!");
    if (i != 0x0102030405060708)
        myerror(-1, "FATAL: incompatible endian!");
    if (fgetc(hFile2) != sizeof(void *))
        myerror(-1, "FATAL: sizeof(void *) incompatible!");
    if (fgetc(hFile2) != sizeof(time_t))
        myerror(-1, "FATAL: sizeof(time_t) incompatible!");
    if (fgetc(hFile2) != 'C')
        myerror(-1, "FATAL: db2 incompatible!");
    if (fgetc(hFile2) != 'W')
        myerror(-1, "FATAL: db2 incompatible!");
    if (!fread(&files2, sizeof(u_int64_t), 1, hFile2))
        myerror(-1, "FATAL: unable to open db2!");
    oldcrc32 = 0xffffffff;
_comparenext1:
    if (!files)
        goto _compare;
    if (!fread(&dnode->fnamelen, sizeof(u_int16_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->fnamecrc, sizeof(u_int32_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->chunkcrc32, sizeof(u_int32_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->crc32, sizeof(u_int32_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->fsize, sizeof(u_int64_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->ctime, sizeof(time_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->mtime, sizeof(time_t), 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->sha1, 20, 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    if (!fread(&dnode->fname, dnode->fnamelen, 1, hFile))
        myerror(-1, "FATAL: unable to parse db1!");
    files--;
    if (!comparedb)
        goto _compare;
    comparedb = 0;
_comparenext2:
    if (!files2)
        goto _comparedone;
    if (!fread(&dnode2->fnamelen, sizeof(u_int16_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->fnamecrc, sizeof(u_int32_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->chunkcrc32, sizeof(u_int32_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->crc32, sizeof(u_int32_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->fsize, sizeof(u_int64_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->ctime, sizeof(time_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->mtime, sizeof(time_t), 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->sha1, 20, 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    if (!fread(&dnode2->fname, dnode2->fnamelen, 1, hFile2))
        myerror(-1, "FATAL: unable to parse db2!");
    files2--;
_compare:
    if (files)
        if (dnode->crc32 < dnode2->crc32)
            goto _comparenext1;
    if ((dnode->crc32 == dnode2->crc32) && (dnode->chunkcrc32 == dnode2->chunkcrc32))
        if (dnode->fsize == dnode2->fsize)
        {
            if (!memcmp(dnode->sha1, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20))
                goto _comparenext2;
            if (!memcmp(dnode2->sha1, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20))
                goto _comparenext2;
            if (!memcmp(dnode->sha1, dnode2->sha1, 20))
                goto _comparenext2;
        }
    if (dnode2->crc32 != oldcrc32)
        printf("%s\n", dnode2->fname);
    oldcrc32 = dnode2->crc32;
    goto _comparenext2;
_comparedone:
    fclose(hFile);
    fclose(hFile2);
    return 0;
}