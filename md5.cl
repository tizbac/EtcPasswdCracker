#include "common.h"

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
char * memcpy( char * dest, char * src, int len)
{
  int i = 0;
  for ( i = 0; i < len; i++ )
  {
    dest[i] = src[i];
  }
  return dest;
}


/* The basic MD5 functions */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    (a) += (b);

#define GET(i) (key[(i)])

// void md5_round(uint* internal_state, const uint* key);
static void md5_round(uint* internal_state, const uint* key) {
  uint a, b, c, d;
  a = internal_state[0];
  b = internal_state[1];
  c = internal_state[2];
  d = internal_state[3];

  /* Round 1 */
  STEP(F, a, b, c, d, GET(0), 0xd76aa478, 7)
  STEP(F, d, a, b, c, GET(1), 0xe8c7b756, 12)
  STEP(F, c, d, a, b, GET(2), 0x242070db, 17)
  STEP(F, b, c, d, a, GET(3), 0xc1bdceee, 22)
  STEP(F, a, b, c, d, GET(4), 0xf57c0faf, 7)
  STEP(F, d, a, b, c, GET(5), 0x4787c62a, 12)
  STEP(F, c, d, a, b, GET(6), 0xa8304613, 17)
  STEP(F, b, c, d, a, GET(7), 0xfd469501, 22)
  STEP(F, a, b, c, d, GET(8), 0x698098d8, 7)
  STEP(F, d, a, b, c, GET(9), 0x8b44f7af, 12)
  STEP(F, c, d, a, b, GET(10), 0xffff5bb1, 17)
  STEP(F, b, c, d, a, GET(11), 0x895cd7be, 22)
  STEP(F, a, b, c, d, GET(12), 0x6b901122, 7)
  STEP(F, d, a, b, c, GET(13), 0xfd987193, 12)
  STEP(F, c, d, a, b, GET(14), 0xa679438e, 17)
  STEP(F, b, c, d, a, GET(15), 0x49b40821, 22)

  /* Round 2 */
  STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
  STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
  STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
  STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
  STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
  STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
  STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
  STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
  STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
  STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
  STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
  STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
  STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
  STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
  STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
  STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

  /* Round 3 */
  STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
  STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
  STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
  STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
  STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
  STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
  STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
  STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
  STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
  STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
  STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
  STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
  STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
  STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
  STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
  STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)

  /* Round 4 */
  STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
  STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
  STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
  STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
  STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
  STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
  STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
  STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
  STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
  STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
  STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
  STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
  STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
  STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
  STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
  STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

  internal_state[0] = a + internal_state[0];
  internal_state[1] = b + internal_state[1];
  internal_state[2] = c + internal_state[2];
  internal_state[3] = d + internal_state[3];
}

typedef struct  {
  uint state[4];
  uint count[2];
  char buffer[64];
} md5ctx_t ;
  
void md5_init(md5ctx_t* ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->count[0] = 0;
  ctx->count[1] = 0;
}

void md5_update(md5ctx_t* ctx,const char * data, uint len)
{
  unsigned int i, index, partLen;
  index = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
  if (( ctx->count[0] += (len << 3)) < (len << 3))
    ctx->count[1]++;
  ctx->count[1] += len >> 29;
  partLen = 64- index;
  if ( len >= partLen )
  {
    memcpy(&ctx->buffer[index], data, partLen);
    md5_round(ctx->state, ctx->buffer);
    for ( i = partLen; i + 63 < len; i+= 64)
    {
      md5_round(ctx->state,&data[i]);
    }
    index = 0;
  }
  else
    i = 0;
  memcpy(&ctx->buffer[index], &data[i], len-i );
}
void Encode( unsigned char *output, unsigned int *input, unsigned int len )
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}
void Decode( unsigned int *output, unsigned char *input, unsigned int len )
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((unsigned int)input[j]) | (((unsigned int)input[j+1]) << 8) |
    (((unsigned int)input[j+2]) << 16) | (((unsigned int)input[j+3]) << 24);
}

void md5_finalize(md5ctx_t* ctx,char * outhash)
{
  unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
  unsigned char bits[8];
  unsigned int index, padLen;
  Encode( bits, ctx->count, 8 );
  index = (unsigned int)((ctx->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  md5_update( ctx,PADDING, padLen );
  md5_update( ctx,bits, 8 );
  Encode( outhash, ctx->state, 16);
}
void md5(const char* restrict msg, uint length_bytes, uint* restrict out,bool init) {
  uint i;
  uint bytes_left;
  char key[64];
  if ( init )
  {
    out[0] = 0x67452301;
    out[1] = 0xefcdab89;
    out[2] = 0x98badcfe;
    out[3] = 0x10325476;
  }

  for (bytes_left = length_bytes;  bytes_left >= 64;
       bytes_left -= 64, msg = &msg[64]) {
    md5_round(out, (const uint*) msg);
  }

  for (i = 0; i < bytes_left; i++) {
    key[i] = msg[i];
  }
  key[bytes_left++] = 0x80;

  if (bytes_left <= 56) {
    for (i = bytes_left; i < 56; key[i++] = 0);
  } else {
    // If we have to pad enough to roll past this round.
    for (i = bytes_left; i < 64; key[i++] = 0);
    md5_round(out, (uint*) key);
    for (i = 0; i < 56; key[i++] = 0);
  }

  ulong* len_ptr = (ulong*) &key[56];
  *len_ptr = length_bytes * 8;
  md5_round(out, (uint*) key);
}




__kernel void md5data(global const char* passwords,global const unsigned int *indexes,global const unsigned int *sizes, global char * out )
{
  int id = get_global_id(0);
  //const char * password = &passwords[indexes[id]];
  char buffer[64];
  char outhash[16];
  char * bufferPtr = buffer;
  int i = 0;
  for ( i = 0; i < sizes[id]; i++ )
  {
    *bufferPtr = passwords[indexes[id]+i];
    bufferPtr++;
  }
  md5(buffer,sizes[id],outhash,true);
  for ( i = 0; i < 16; i++ )
  {
    out[id*16+i] = outhash[i];
  }
  //&out[id*16]
}


int strlen(const char * str)
{
  int len = 0;
  while ( str[len] != 0x00 )
    len++;
  
  return len;
}
char * __stpncpy(char * dest, const char * src, int n)
{
  int i = 0;
  char * term = 0x0;
  for ( i = 0; i < n ; i++ )
  {
    if ( *src != 0x00 )
      *dest = *src;
    else
    {
      if ( term == 0x0 )
        term == dest;
      *dest = 0x00;
    }
    dest++;
    src++;
  }
  *dest = 0x00;
  return term == 0x0 ? dest : term;
}

int MAX( int v1, int v2 )
{
  if ( v1 > v2 )
    return v1;
  else
    return v2;
}
int MIN( int v1, int v2 )
{
  if ( v1 < v2 )
    return v1;
  else
    return v2;
}
char * memset( char * ptr, int value, int num)
{
  int i = 0;
  for ( i = 0; i < num; i++ )
    ptr[i] = value;
  return ptr;
}

char *
md5crypt (
      char  *  key,
     char  *  salt,
     char  *  buffer,
     int buflen)
{
 char md5_salt_prefix[] = "$1$";

/* Table with characters for base64 transformation.  */
 char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  
  unsigned char alt_result[16]
    __attribute__ ((__aligned__ (__alignof__ (unsigned int))));
//   struct md5_ctx ctx;
//   struct md5_ctx alt_ctx;
    
    
  md5ctx_t ctx;
  md5ctx_t alt_ctx;
    
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = 0x0;
  char *copied_salt = 0x0;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  /*if (strncmp (md5_salt_prefix, salt, sizeof (md5_salt_prefix) - 1) == 0) WARNING: NO SALT PREFIX ALLOWED
    /* Skip salt prefix.  */
   // salt += sizeof (md5_salt_prefix) - 1;

  salt_len = strlen(salt);
  key_len = strlen (key);
   char tmp[64];
  if ((key - (char *) 0) % __alignof__ (unsigned int) != 0)
    {
      
      key = copied_key =
        memcpy (tmp + __alignof__ (unsigned int)
                - (tmp - (char *) 0) % __alignof__ (unsigned int),
                key, key_len);
      //assert ((key - (char *) 0) % __alignof__ (unsigned int) == 0);
    }

  if ((salt - (char *) 0) % __alignof__ (unsigned int) != 0)
    {

      salt = copied_salt =
        memcpy (tmp + __alignof__ (unsigned int)
                - (tmp - (char *) 0) % __alignof__ (unsigned int),
                salt, salt_len);
     // assert ((salt - (char *) 0) % __alignof__ (unsigned int) == 0);
    }



  /* Add the key string.  */
  md5_init(&ctx);
  md5_update(&ctx, key, key_len);

  /* Because the SALT argument need not always have the salt prefix we
     add it separately.  */
  md5_update (&ctx,md5_salt_prefix, sizeof (md5_salt_prefix) - 1);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility which existing solutions).  */
  md5_update (&ctx,salt, salt_len);


  /* Compute alternate MD5 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
//   __md5_init_ctx (&alt_ctx);

  /* Add key.  */
  md5_init(&alt_ctx);
  md5_update (&alt_ctx,key, key_len);

  /* Add salt.  */
  md5_update (&alt_ctx,salt, salt_len);

  /* Add key again.  */
  md5_update (&alt_ctx,key, key_len);

  /* Now get result of this (16 bytes) and add it to the other
     context.  */
  md5_finalize(&alt_ctx,alt_result);
 // memcpy(&alt_result,alt_ctx,16);
//   __md5_finish_ctx (&alt_ctx, alt_result);

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 16; cnt -= 16)
    md5_update (&ctx,alt_result, 16);
  md5_update (&ctx,alt_result, cnt);

  /* For the following code we need a NUL byte.  */
  *alt_result = '\0';

  /* The original implementation now does something weird: for every 1
     bit in the key the first 0 is added to the buffer, for every 0
     bit the first character of the key.  This does not seem to be
     what was intended but we have to follow this to be compatible.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    md5_update (&ctx,(cnt & 1) != 0 ? (const char *) alt_result : key, 1
                         );

  /* Create intermediate result.  */
  md5_finalize( &ctx, alt_result);
  //memcpy ( alt_result , ctx, 16);

  /* Now comes another weirdness.  In fear of password crackers here
     comes a quite long loop which just processes the output of the
     previous round again.  We cannot ignore this here.  */
  char val_dummy[1];
  for (cnt = 0; cnt < 1000; ++cnt)
    {
      /* New context.  */
      //__md5_init_ctx (&ctx);
      md5_init(&ctx);
      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        md5_update (&ctx,key, key_len);
      else
        md5_update (&ctx,alt_result, 16);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        md5_update (&ctx,salt, salt_len);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        md5_update (&ctx,key, key_len);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        md5_update (&ctx,alt_result, 16);
      else
        md5_update (&ctx,key, key_len);

      /* Create intermediate result.  */
      md5_finalize(&ctx,alt_result);
    //  memcpy(alt_result,ctx,16);
    }
  cp = buffer;
  /* Now we can construct the result string.  It consists of three
     parts.  */
  memcpy(cp,md5_salt_prefix,sizeof (md5_salt_prefix)-1);
  cp += sizeof (md5_salt_prefix)-1;
  memcpy(cp,salt,salt_len);
  cp += salt_len;

  *cp = '$';
  cp++;



#define b64_from_24bit(B2, B1, B0, N)                                         \
  do {                                                                        \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);                       \
    int n = (N);                                                              \
    while (n-- > 0 && buflen > 0)                                             \
      {                                                                       \
        *cp++ = b64t[w & 0x3f];                                               \
        --buflen;                                                             \
        w >>= 6;                                                              \
      }                                                                       \
  } while (0)


  b64_from_24bit (alt_result[0], alt_result[6], alt_result[12], 4);
  b64_from_24bit (alt_result[1], alt_result[7], alt_result[13], 4);
  b64_from_24bit (alt_result[2], alt_result[8], alt_result[14], 4);
  b64_from_24bit (alt_result[3], alt_result[9], alt_result[15], 4);
  b64_from_24bit (alt_result[4], alt_result[10], alt_result[5], 4);
  b64_from_24bit (0, 0, alt_result[11], 2);
  if (buflen <= 0)
    {
      //__set_errno  (ERANGE);
      buffer = 0x0;
    }
  else
    *cp = '\0';         /* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the MD5 implementation as well.  */


  return buffer;
}


__kernel void computeHashes(global const char* passwords,global const unsigned int *indexes,global const unsigned int *sizes,global const char * salt,global const char * correcthash,global char * correctpass,global int * correctid)
{
  int id = get_global_id(0);
  //const char * password = &passwords[indexes[id]];
  char buffer[64];
  char outhash[64];
  char * bufferPtr = buffer;
  char salttest[9];
  
  int i = 0;
  for ( i = 0; i < 9; i++ )
  {
    salttest[i] = salt[i];
    
  }
  salttest[8] = 0;
  for ( i = 0; i < sizes[id]; i++ )
  {
    *bufferPtr = passwords[indexes[id]+i];
    bufferPtr++;
  }
  md5crypt(buffer,salttest,outhash,64);
  char correcthashLOC[64];
  for ( i = 0; i < 64; i++ )
  {
    if ( correcthash[i] != 0x00 )
      correcthashLOC[i] = correcthash[i];
    else
    {
      correcthashLOC[i] = 0x0;
      break;
    }
  }
    /*if ( id == 0 )
    {
         for ( i = 0; outhash[i] != 0; i++ )
          {
            correctpass[i] = outhash[i];
          }
          correctpass[i] = 0;
  
    }*/
  if ( strlen(outhash) != strlen(correcthashLOC) )
  {
     
    return;
  }
  
  for ( i = 0; outhash[i] != 0; i++ )
  {
    if ( outhash[i] != correcthashLOC[i] )
    {
    //  correctpass[i] = i;
      return;
    }
  }
 
  for ( i = 0; i < sizes[id]+1 ; i++ )
 {
   correctpass[i] = passwords[indexes[id]+i];
 }
  
  correctid[0] = id;
  //&out[id*16]
}
