/*
 *	%W%
 *
 *	md5 [ files ... ]
 *
 *	MD5 message digest.
 *
 *	Written from the decription in _Network Security_, Kaufman et al
 *	and RFC 1321.  The description in _Network Security_ is just wrong.
 *
 *
 *	Boyd Roberts
 *	November '95
 *
 *
 *	The following, taken from RFC 1321, is required to be attached
 *	for licencing reasons:
 *
 *		derived from the RSA Data Security, Inc.
 *		MD5 Message-Digest Algorithm
 */

#include	<stdio.h>
#include <stdlib.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<string.h>
#include <unistd.h>
#include <errno.h>

#include "md5.h"

#define SYSERROR	(-1)

/*
 *	32 bit unsigned integer
 */
#if	__osf__ && __alpha
typedef unsigned int	u32;
#else
typedef unsigned long	u32;
#endif

typedef unsigned char	uchar;

#define bzero(b, n)	memset(b, '\0', n)

/*
 *	Message block sizes.
 */
#define MSG_BITS	512
#define MSG_BYTES	(MSG_BITS / 8)
#define MSG_WORDS	(MSG_BYTES / sizeof(u32))

/*
 *	Number of words in the digest.
 */
#define DIGEST_WORDS	4

/*
 *	Byte offset in the message block for the message size in bits.
 */
#define MSG_LEN1_BYTE	(MSG_BYTES - sizeof(u32))
#define MSG_LEN0_BYTE	(MSG_LEN1_BYTE - sizeof(u32))

/*
 *	Constants and function required for each round.
 */
typedef struct md5tab
{
	u32	t;			/* constant */
	u32	(*f)(u32, u32, u32);	/* function */
	int	i;			/* message block word */
	int	s;			/* shift */
}
		md5tab;

/*
 *	Digest mangling functions.
 */
u32		F(u32, u32, u32);
u32		G(u32, u32, u32);
u32		H(u32, u32, u32);
u32		I(u32, u32, u32);

/*
 *	MD5 constants:
 *
 *		for (i = 1; i <= 64; i++)
 *			t[i - 1] = floor((4294967296.0 * fabs(sin((double)i)));
 *
 *		4294967296.0 == 2 ^ 32
 */
md5tab		rounds[]	=
{
	/* pass 1 */
	{ 0xd76aa478, F,  0,  7, },
	{ 0xe8c7b756, F,  1, 12, },
	{ 0x242070db, F,  2, 17, },
	{ 0xc1bdceee, F,  3, 22, },
	{ 0xf57c0faf, F,  4,  7, },
	{ 0x4787c62a, F,  5, 12, },
	{ 0xa8304613, F,  6, 17, },
	{ 0xfd469501, F,  7, 22, },
	{ 0x698098d8, F,  8,  7, },
	{ 0x8b44f7af, F,  9, 12, },
	{ 0xffff5bb1, F, 10, 17, },
	{ 0x895cd7be, F, 11, 22, },
	{ 0x6b901122, F, 12,  7, },
	{ 0xfd987193, F, 13, 12, },
	{ 0xa679438e, F, 14, 17, },
	{ 0x49b40821, F, 15, 22, },
	/* pass 2 */
	{ 0xf61e2562, G,  1,  5, },
	{ 0xc040b340, G,  6,  9, },
	{ 0x265e5a51, G, 11, 14, },
	{ 0xe9b6c7aa, G,  0, 20, },
	{ 0xd62f105d, G,  5,  5, },
	{ 0x02441453, G, 10,  9, },
	{ 0xd8a1e681, G, 15, 14, },
	{ 0xe7d3fbc8, G,  4, 20, },
	{ 0x21e1cde6, G,  9,  5, },
	{ 0xc33707d6, G, 14,  9, },
	{ 0xf4d50d87, G,  3, 14, },
	{ 0x455a14ed, G,  8, 20, },
	{ 0xa9e3e905, G, 13,  5, },
	{ 0xfcefa3f8, G,  2,  9, },
	{ 0x676f02d9, G,  7, 14, },
	{ 0x8d2a4c8a, G, 12, 20, },
	/* pass 3 */
	{ 0xfffa3942, H,  5,  4, },
	{ 0x8771f681, H,  8, 11, },
	{ 0x6d9d6122, H, 11, 16, },
	{ 0xfde5380c, H, 14, 23, },
	{ 0xa4beea44, H,  1,  4, },
	{ 0x4bdecfa9, H,  4, 11, },
	{ 0xf6bb4b60, H,  7, 16, },
	{ 0xbebfbc70, H, 10, 23, },
	{ 0x289b7ec6, H, 13,  4, },
	{ 0xeaa127fa, H,  0, 11, },
	{ 0xd4ef3085, H,  3, 16, },
	{ 0x04881d05, H,  6, 23, },
	{ 0xd9d4d039, H,  9,  4, },
	{ 0xe6db99e5, H, 12, 11, },
	{ 0x1fa27cf8, H, 15, 16, },
	{ 0xc4ac5665, H,  2, 23, },
	/* pass 4 */
	{ 0xf4292244, I,  0,  6, },
	{ 0x432aff97, I,  7, 10, },
	{ 0xab9423a7, I, 14, 15, },
	{ 0xfc93a039, I,  5, 21, },
	{ 0x655b59c3, I, 12,  6, },
	{ 0x8f0ccc92, I,  3, 10, },
	{ 0xffeff47d, I, 10, 15, },
	{ 0x85845dd1, I,  1, 21, },
	{ 0x6fa87e4f, I,  8,  6, },
	{ 0xfe2ce6e0, I, 15, 10, },
	{ 0xa3014314, I,  6, 15, },
	{ 0x4e0811a1, I, 13, 21, },
	{ 0xf7537e82, I,  4,  6, },
	{ 0xbd3af235, I, 11, 10, },
	{ 0x2ad7d2bb, I,  2, 15, },
	{ 0xeb86d391, I,  9, 21, },
};

/*
 *	Initial little endian message digest.
 *	They make sense if written big endian.
 */
u32		d[DIGEST_WORDS]	=
{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
};

char		*my_name;
int		ok		= 0;

/*
 *	32 bit unsigned to little endian.
 */
void
unpack(u32 u, uchar *b)
{
	b[0] = u & 0xFF;
	b[1] = (u >> 8) & 0xFF;
	b[2] = (u >> 16) & 0xFF;
	b[3] = (u >> 24) & 0xFF;
}

/*
 *	Little endian to 32 bit unsigned.
 */
u32
pack(uchar *b)
{
	return ((u32)b[3] << 24) | ((u32)b[2] << 16) | ((u32)b[1] << 8) | b[0];
}

u32
F(u32 x, u32 y, u32 z)
{
	return (x & y) | (~x & z);
}

u32
G(u32 x, u32 y, u32 z)
{
	return (x & z) | (y & ~z);
}

u32
H(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

u32
I(u32 x, u32 y, u32 z)
{
	return y ^ (x | ~z);
}

/*
 *	Print the message digest (little endian).
 */
int md5print(u32 *d, char *hashstr, size_t hash_size)
{
	int	i;
	char *p = hashstr;
	
	for (i = 0; i < DIGEST_WORDS; i++)
	{
		uchar	b[4];

		unpack(d[i], b);
		snprintf(p,hash_size,"%02x%02x%02x%02x", b[0], b[1], b[2], b[3]);
		p+=8;
		hash_size-=8;
	}

	return 0;
}

/*
 *	Compute the message digest for a message block.
 */
void
md5block(uchar *b, u32 *d)
{
	u32	*m;
	int	i;
	md5tab	*rp;
	u32	old[DIGEST_WORDS];
	u32	message[MSG_WORDS];

	m = message;

	for (i = 0; i < MSG_BYTES; i += sizeof *m)
	{
		*m = pack(b);
		b += sizeof(*m);
		m++;
	}

	m = message;
	rp = rounds;

	/* save current digest */
	old[0] = d[0];
	old[1] = d[1];
	old[2] = d[2];
	old[3] = d[3];

	for (i = 0; i < sizeof rounds / sizeof rounds[0]; i++)
	{
		u32	x;

		x = d[-i & 3] + (*rp->f)(d[(1 - i) & 3], d[(2 - i) & 3], d[(3 - i) & 3]) + m[rp->i] + rp->t;

		/* 32 bit rotate */
		x = (x << rp->s) | (x >> (32 - rp->s));
		d[-i & 3] = d[(1 - i) & 3] + x;
		rp++;
	}

	/* add previous digest to current  */
	d[0] += old[0];
	d[1] += old[1];
	d[2] += old[2];
	d[3] += old[3];
}




int md5_str(const char *instr, char *hashstr, size_t hash_size)
{
	uchar	buf[MSG_BYTES * 64];
	uchar	*mb;
	uchar	*me;
	u32	digest[DIGEST_WORDS];
	u32	bits[2];
	int	i;

	/* initial digest */
	for (i = 0; i < DIGEST_WORDS; i++)
		digest[i] = d[i];

	/* size of message in bits */
	bits[0] = bits[1] = 0;

	mb = me = buf;

	for (;;)
	{
		if (mb >= me)
		{
			int	n;

			switch (n = *instr)
			{
			case 0:
				mb = me = buf;
				break;
	
			default:
				mb = buf;
				me = &buf[n];

				/* update size in bits*/
				n <<= 3;
				if ((bits[0] += n) < n)
					bits[1]++;
			}

			instr++;
		}

		if (me - mb < MSG_BYTES)
			break;

		/* process whole block */
		md5block(mb, digest);
		mb += MSG_BYTES;
	}

	/* pad message */
	*me++ = 0x80;

	if ((me - mb) > MSG_LEN0_BYTE)
	{
		/* digest this block and substitute a padded block */
		bzero(me, MSG_BYTES - (me - mb));
		md5block(mb, digest);
		bzero(mb, MSG_LEN0_BYTE);
	}
	else
		bzero(me, MSG_LEN0_BYTE - (me - mb));

	/* append size in bits */
	unpack(bits[0], &mb[MSG_LEN0_BYTE]);
	unpack(bits[1], &mb[MSG_LEN1_BYTE]);
	md5block(mb, digest);
	md5print(digest, hashstr, hash_size);

	return 0;
}


/*
 *	Compute the message digest for a file.
 */
void
md5(const char *file, int fd, char *hashstr, size_t hash_size)
{
	uchar	buf[MSG_BYTES * 64];
	uchar	*mb;
	uchar	*me;
	u32	digest[DIGEST_WORDS];
	u32	bits[2];
	int	i;

	/* initial digest */
	for (i = 0; i < DIGEST_WORDS; i++)
		digest[i] = d[i];

	/* size of message in bits */
	bits[0] = bits[1] = 0;

	mb = me = buf;

	for (;;)
	{
		if (mb >= me)
		{
			int	n;

			switch (n = read(fd, buf, sizeof buf))
			{
			case SYSERROR:
//				fprintf(stderr,"Could not read %s\n",file);
				return;

			case 0:
				mb = me = buf;
				break;
	
			default:
				mb = buf;
				me = &buf[n];

				/* update size in bits*/
				n <<= 3;
				if ((bits[0] += n) < n)
					bits[1]++;
			}
		}

		if (me - mb < MSG_BYTES)
			break;

		/* process whole block */
		md5block(mb, digest);
		mb += MSG_BYTES;
	}

	/* pad message */
	*me++ = 0x80;

	if ((me - mb) > MSG_LEN0_BYTE)
	{
		/* digest this block and substitute a padded block */
		bzero(me, MSG_BYTES - (me - mb));
		md5block(mb, digest);
		bzero(mb, MSG_LEN0_BYTE);
	}
	else
		bzero(me, MSG_LEN0_BYTE - (me - mb));

	/* append size in bits */
	unpack(bits[0], &mb[MSG_LEN0_BYTE]);
	unpack(bits[1], &mb[MSG_LEN1_BYTE]);
	md5block(mb, digest);
	md5print(digest, hashstr, hash_size);
}

/*-----------------------------------------------------------------\
 Function Name	: md5_file
 Returns Type	: int
 	----Parameter List
	1. char *fname, 
	2.  char *hashstr, 
	3.  size_t hash_size , 
 	------------------
 Exit Codes	: 
	returns -1 if it couldn't open the file.
 Side Effects	: 
--------------------------------------------------------------------
 Comments:
 
--------------------------------------------------------------------
 Changes:
 
\------------------------------------------------------------------*/
int md5_file( const char *fname, char *hashstr, size_t hash_size )
{
	int		fd;

	if ((fd = open(fname, O_RDONLY)) == SYSERROR)
			{
//				fprintf(stderr,"md5_file:ERROR: Could not open '%s'(%s)" ,fname ,strerror(errno));
				return -1;
			}
	
	md5(fname, fd, hashstr, hash_size);
	close(fd);

	return 0;
}
