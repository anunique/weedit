#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS_64

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "../include/structs.h"

void *load_db(weedit_db *db, char *dbname)
{
    FILE *hFile;
    u_int8_t tmp[5000];
    u_int32_t i;
    u_int64_t files;
    dlink_dnode *dnode, *dnode2;
    dlink_fnode *fnode, *fnode2;
    u_int16_t datasize;
    dlink_dnode **checksumptr = db->checksumptr;
    dlink_fnode **fnameptr = db->fnameptr;
    u_int16_t entryptr, entryptr2;
    dlink_dlist *checksum;
    dlink_flist *fname;
    fname = &db->fname;
    checksum = &db->checksum;
    hFile = fopen(dbname, "rb");
    if (!hFile)
        return 0;

    if (!fread(tmp, 8, 1, hFile))
        return "FATAL: unable to open db!";
    if (memcmp(&tmp, "WEEDIT\4\0", 8))
        return "FATAL: db incompatible!";
    if (!fread(&i, 4, 1, hFile))
        return "FATAL: unable to open db!";
    if (i != 0x01020304)
        return "FATAL: incompatible endian!";
    if (fgetc(hFile) != sizeof(void *))
        return "FATAL: sizeof(void *) incompatible!";
    if (fgetc(hFile) != sizeof(time_t))
        return "FATAL: sizeof(time_t) incompatible!";
    if (fgetc(hFile) != 'C')
        return "FATAL: db incompatible!";
    if (fgetc(hFile) != 'W')
        return "FATAL: db incompatible!";
    if (!fread(&files, sizeof(u_int64_t), 1, hFile))
        return "FATAL: unable to open db!";
    if (files)
    {
        if (!fread(&datasize, sizeof(u_int16_t), 1, hFile))
            return "FATAL: unable to open db!";
        fnode2 = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
        if (!fnode2)
            return "Fatal: out of memory";
        dnode2 = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + datasize);
        if (!dnode2)
            return "Fatal: out of memory";
        fnode2->data = dnode2;
        dnode2->fnamelen = datasize;
        if (!fread(&dnode2->fnamecrc, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->chunkid, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->crc32, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->fsize, sizeof(u_int64_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->ctime, sizeof(time_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->mtime, sizeof(time_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->sha1, 20, 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode2->fname, datasize, 1, hFile))
            return "FATAL: unable to open db!";
        fname->head = fnode2;
        fname->tail = fnode2;
        fnameptr[0] = fnode2;
        entryptr = (dnode2->fnamecrc & 0xffff0000) >> 16;
        fnameptr[entryptr] = fnode2;
        checksum->head = dnode2;
        checksumptr[0] = dnode2;
        entryptr = (dnode2->crc32 & 0xffff0000) >> 16;
        checksumptr[entryptr] = dnode2;
        files--;
        while (files)
        {
            if (!fread(&datasize, sizeof(u_int16_t), 1, hFile))
                return "FATAL: unable to open db!";
            fnode = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
            if (!fnode)
                return "Fatal: out of memory";
            dnode = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + datasize);
            if (!dnode)
                return "Fatal: out of memory";
            fnode->data = dnode;
            dnode->fnamelen = datasize;
            if (!fread(&dnode->fnamecrc, sizeof(u_int32_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->chunkid, sizeof(u_int32_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->crc32, sizeof(u_int32_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->fsize, sizeof(u_int64_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->ctime, sizeof(time_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->mtime, sizeof(time_t), 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->sha1, 20, 1, hFile))
                return "FATAL: unable to open db!";
            if (!fread(&dnode->fname, datasize, 1, hFile))
                return "FATAL: unable to open db!";
            entryptr = (dnode->crc32 & 0xffff0000) >> 16;
            if (!checksumptr[entryptr])
                checksumptr[entryptr] = dnode;
            dnode2->next = dnode;
            dnode->prev = dnode2;
            entryptr = (dnode->fnamecrc & 0xffff0000) >> 16;
            entryptr2 = entryptr;
            while (!fnameptr[entryptr2])
                entryptr2--;
            fnode2 = fnameptr[entryptr2];
            while (1)
            {
                if (dnode->fnamecrc < fnode2->data->fnamecrc)
                {
                    if (fnode2 == fnameptr[entryptr] || !fnameptr[entryptr])
                        fnameptr[entryptr] = fnode;
                    if (fname->head == fnode2)
                    {
                        fnode->next = fname->head;
                        fnode->next->prev = fnode;
                        fname->head = fnode;
                        fnameptr[0] == fnode;
                    }
                    else
                    {
                        if (fnode2->prev)
                            fnode2->prev->next = fnode;
                        fnode->next = fnode2;
                        fnode->prev = fnode2->prev;
                        fnode2->prev = fnode;
                    }
                    break;
                }
                fnode2 = fnode2->next;
                if (!fnode2)
                {
                    fnode->prev = fname->tail;
                    fnode->prev->next = fnode;
                    fname->tail = fnode;
                    if (!fnameptr[entryptr])
                        fnameptr[entryptr] = fnode;
                    break;
                }
            }
            dnode2 = dnode;
            files--;
        }
    }
    checksum->tail = dnode2;
    fclose(hFile);
    return 0;
}

void *save_db(weedit_db *db, char *dbname)
{
    u_int64_t files = 0, checksums;
    FILE *hFile;
    u_int32_t i;
    for (dlink_dnode *dnode = db->checksum.head; dnode != NULL; dnode = dnode->next)
        if (dnode->fnamelen)
            files++;

    if ((hFile = fopen(dbname, "wb")) == 0)
        return "FATAL: unable to save database!";

    checksums = files;
    if (fwrite("WEEDIT\4\0", 8, 1, hFile) != 1)
        return "FATAL: unable to createa db!";
    i = 0x01020304;
    if (fwrite(&i, 4, 1, hFile) != 1)
        return "FATAL: unable to createa db!";
    if (fputc(sizeof(void *), hFile) != sizeof(void *))
        return "FATAL: unable to createa db!";
    if (fputc(sizeof(time_t), hFile) != sizeof(time_t))
        return "FATAL: unable to createa db!";
    if (fputc('C', hFile) != 'C')
        return "FATAL: unable to createa db!";
    if (fputc('W', hFile) != 'W')
        return "FATAL: unable to createa db!";
    if (fwrite(&files, sizeof(u_int64_t), 1, hFile) != 1)
        return "FATAL: unable to createa db!";
    for (dlink_dnode *dnode = db->checksum.head; dnode != NULL; dnode = dnode->next)
        if (dnode->fnamelen)
        {
            if (checksums == 0)
                return "FATAL: db writing error!";
            checksums--;
            if (fwrite(&dnode->fnamelen, sizeof(u_int16_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->fnamecrc, sizeof(u_int32_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->chunkid, sizeof(u_int32_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->crc32, sizeof(u_int32_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->fsize, sizeof(u_int64_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->ctime, sizeof(time_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->mtime, sizeof(time_t), 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->sha1, 20, 1, hFile) != 1)
                return "FATAL: unable to createa db!";
            if (fwrite(&dnode->fname, dnode->fnamelen, 1, hFile) != 1)
                return "FATAL: unable to createa db!";
        }
    fclose(hFile);
    return 0;
}