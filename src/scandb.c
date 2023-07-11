#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../include/structs.h"

void scandb(weedit_db *db)
{
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        dlink_dnode *dnode = db->checksumptr[i];
        dlink_dnode *dnode2 = 0;
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
                dnode2->fnamelen = 0;
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
    _deldupesdone:
    }
}