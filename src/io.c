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
    FILE *hFile = fopen(dbname, "rb");
    if (!hFile)
        return 0;
    u_int8_t fileheader[8];
    if (!fread(fileheader, 8, 1, hFile))
        return "FATAL: unable to open db!";
    if (memcmp(&fileheader, "WEEDIT\4\0", 8))
        return "FATAL: db incompatible!";
    u_int64_t j;
    if (!fread(&j, 8, 1, hFile))
        return "FATAL: unable to open db!";
    if (j != 0x0102030405060708)
        return "FATAL: incompatible endian!";
    if (fgetc(hFile) != sizeof(void *))
        return "FATAL: sizeof(void *) incompatible!";
    if (fgetc(hFile) != sizeof(time_t))
        return "FATAL: sizeof(time_t) incompatible!";
    if (fgetc(hFile) != 'C')
        return "FATAL: db incompatible!";
    if (fgetc(hFile) != 'W')
        return "FATAL: db incompatible!";
    u_int64_t files;
    if (!fread(&files, sizeof(files), 1, hFile))
        return "FATAL: unable to open db!";
    u_int16_t fnamelen;
    u_int32_t dnode_idx_old = -1;
    dlink_dnode *dnode = 0;
    while (files)
    {
        if (!fread(&fnamelen, sizeof(u_int16_t), 1, hFile))
            return "FATAL: unable to open db!";
        dlink_fnode *fnode_new = (dlink_fnode *)calloc(1, sizeof(dlink_fnode));
        if (!fnode_new)
            return "Fatal: out of memory";
        dlink_dnode *dnode_new = (dlink_dnode *)calloc(1, sizeof(dlink_dnode) + fnamelen);
        if (!dnode_new)
            return "Fatal: out of memory";
        fnode_new->data = dnode_new;
        dnode_new->fnamelen = fnamelen;
        if (!fread(&dnode_new->fnamecrc, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->chunkcrc32, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->crc32, sizeof(u_int32_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->fsize, sizeof(u_int64_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->ctime, sizeof(time_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->mtime, sizeof(time_t), 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->sha1, 20, 1, hFile))
            return "FATAL: unable to open db!";
        if (!fread(&dnode_new->fname, fnamelen, 1, hFile))
            return "FATAL: unable to open db!";
        u_int32_t dnode_idx = dnode_new->chunkcrc32 & TABLE_MASK;
        if (dnode_idx_old != dnode_idx)
        {
            dnode = db->checksumptr[dnode_idx];
            dnode_idx_old = dnode_idx;
            if (dnode == 0)
            {
                db->checksumptr[dnode_idx] = dnode_new;
            }
            dnode = dnode_new;
        }
        else
        {
            dnode->next = dnode_new;
            dnode_new->prev = dnode;
            dnode = dnode_new;
        }
        dlink_fnode *fnode_cur = db->fnameptr[dnode_new->fnamecrc & TABLE_MASK];
        dlink_fnode *fnode_old = 0;
    _find_file:
        if (!fnode_cur)
            goto _new_file;
        if (dnode_new->fnamecrc <= fnode_cur->data->fnamecrc)
            goto _new_file;
        fnode_old = fnode_cur;
        fnode_cur = fnode_cur->next;
        goto _find_file;
    _new_file:
        if (fnode_old == 0)
        {
            db->fnameptr[dnode_new->fnamecrc & TABLE_MASK] = fnode_new;
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
        files--;
    }
    fclose(hFile);
    return 0;
}

void *save_db(weedit_db *db, char *dbname)
{
    u_int64_t files = 0;
    FILE *hFile;
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        dlink_dnode *dnode = db->checksumptr[i];
        while (dnode)
        {
            if (dnode->fnamelen)
                files++;
            dnode = dnode->next;
        }
    }
    if ((hFile = fopen(dbname, "wb")) == 0)
        return "FATAL: unable to save database!";
    if (fwrite("WEEDIT\4\0", 8, 1, hFile) != 1)
        return "FATAL: unable to createa db!";
    u_int64_t j = 0x0102030405060708;
    if (fwrite(&j, 8, 1, hFile) != 1)
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
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        dlink_dnode *dnode = db->checksumptr[i];
        while (dnode)
        {
            if (dnode->fnamelen)
            {
                if (fwrite(&dnode->fnamelen, sizeof(u_int16_t), 1, hFile) != 1)
                    return "FATAL: unable to createa db!";
                if (fwrite(&dnode->fnamecrc, sizeof(u_int32_t), 1, hFile) != 1)
                    return "FATAL: unable to createa db!";
                if (fwrite(&dnode->chunkcrc32, sizeof(u_int32_t), 1, hFile) != 1)
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
            dnode = dnode->next;
        }
    }
    fclose(hFile);
    return 0;
}