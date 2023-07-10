#ifndef __STRUCTS_H
#define __STRUCTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>

#define CHUNK_SIZE 65536
#define TABLE_SIZE 65536
#define TABLE_MASK (TABLE_SIZE - 1)

	extern u_int8_t quiet, deldupes, forcescan;
	extern u_int8_t *buf;
	extern u_int64_t bytes, bytes2, dupes;

	typedef struct _dlink_fnode dlink_fnode;
	typedef struct _dlink_dnode dlink_dnode;

#pragma pack(push,1)
	struct _dlink_dnode
	{
		dlink_dnode *prev;
		dlink_dnode *next;
		u_int64_t fsize;
		u_int8_t sha1[20];
		u_int32_t crc32;
		u_int32_t chunkcrc32;
		time_t ctime;
		time_t mtime;
		u_int32_t fnamecrc;
		u_int16_t fnamelen;
		char fname[];
	};
#pragma pack(pop)

	struct _dlink_fnode
	{
		dlink_fnode *prev;
		dlink_fnode *next;
		dlink_dnode *data;
	};

	typedef struct
	{
		dlink_dnode *checksumptr[TABLE_SIZE];
		dlink_fnode *fnameptr[TABLE_SIZE];
	} weedit_db;

#ifdef __cplusplus
}
#endif

#endif /* __STRUCTS_H*/
