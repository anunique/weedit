// some modifications in the original version!!! -CW-

#ifndef ___MD5_H
#define ___MD5_H

#include <sys/types.h>

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16

typedef struct MD5Context {
	u_int32_t state[4];			/* state */
	u_int32_t count[2];			/* number of bits, mod 2^64 */
	u_int8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} MD5_CTX;

/* include <sys/cdefs.h> */

/* __BEGIN_DECLS */
void	 MD5_Init(MD5_CTX *);
void	 MD5_Update(MD5_CTX *, const u_int8_t *, size_t)
/*		__attribute__((__bounded__(__string__,2,3)))*/;
void	 MD5_Final(u_int8_t [MD5_DIGEST_LENGTH], MD5_CTX *)
/*		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_LENGTH)))*/;
void	 MD5_Transform(u_int32_t [4], const u_int8_t [MD5_BLOCK_LENGTH])
/*		__attribute__((__bounded__(__minbytes__,1,4)))*/
/*		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_LENGTH)))*/;
/* __END_DECLS */

#endif /* __MD5_H */
