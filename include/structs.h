#ifndef __STRUCTS_H
#define __STRUCTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define CHUNK_SIZE 65536
#define TABLE_SIZE 65536
#define TABLE_MASK (TABLE_SIZE - 1)

typedef struct _dlink_fnode dlink_fnode;
typedef struct _dlink_dnode dlink_dnode;

#pragma pack(1)
struct _dlink_dnode {
	dlink_dnode *prev;
	dlink_dnode *next;
	unsigned long chunkid;
	unsigned long crc32;
	unsigned long long fsize;
	unsigned char sha1[20];
	time_t ctime;
	time_t mtime;
	unsigned long fnamecrc;
	unsigned short fnamelen;
	unsigned char fname[];
};
#pragma pack()

struct _dlink_fnode {
	dlink_fnode *prev;
	dlink_fnode *next;
	dlink_dnode *data;
};

typedef struct {
	dlink_dnode *head;
	dlink_dnode *tail;
} dlink_dlist;

typedef struct {
	dlink_fnode *head;
	dlink_fnode *tail;
} dlink_flist;

#ifdef __cplusplus
}
#endif

#endif /* __STRUCTS_H*/
