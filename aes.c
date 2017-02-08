/*
 * AES-128
 * author: Aman Wardak
 */

#include <stdio.h>      // printf
#include <stdlib.h>     // exit
#include <string.h>     // memcpy, memset
#include <stdint.h>     // uint8_t

// for debugging
#define DEBUG_KEY_FLAG 0
#define DEBUG_CIPHER_STATE_FLAG 0

#define DEBUG_KEY(...) do {         \
    if (DEBUG_KEY_FLAG) {           \
        printf(__VA_ARGS__);        \
    }                               \
} while(0)

#define DEBUG_CIPHER_STATE(a) do {  \
    if (DEBUG_CIPHER_STATE_FLAG) {  \
        for (int r=0; r<4; r++) {   \
            printf(a "%02x%02x%02x%02x\n",  \
                    state[r][0], state[r][1], state[r][2], state[r][3]);    \
        }                           \
    }                               \
} while(0)

/*
 * the following code to multiply is taken from:
 *   https://github.com/kokke/tiny-AES128-C/blob/master/aes.c
 */
uint8_t xtime(uint8_t x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}
#define MULTIPLY_AS_A_FUNCTION 0
// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// AES defined block size
#define BLOCK_SIZE 16           // AES block sizes are 16 bytes = 128 bits
#define KEY_SCHED_SIZE 176      // 16 (key size) * 11 (10 rounds + 1)

// sBox as defined in AES standard
const uint8_t sBox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
// the inverse S-box
const uint8_t invSBox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
// rcon is a given round constant used in key expansion
const uint8_t rcon[] = {
    0x00,       // unused/placeholder
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36
};
// lookup table for multiplication by 2 according to AES arithmetic
// ref: ://en.wikipedia.org/wiki/Rijndael_mix_columns 
const uint8_t multBy2[] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};
// lookup table for multiplication by 3 according to AES arithmetic
// ref: ://en.wikipedia.org/wiki/Rijndael_mix_columns 
const uint8_t multBy3[] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};
// lookup table for multiplication by 9 according to AES arithmetic
const uint8_t multBy9[] = {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
};
// lookup table for multiplication by 11 according to AES arithmetic
const uint8_t multBy11[] = {
0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
};
// lookup table for multiplication by 13 according to AES arithmetic
const uint8_t multBy13[] = {
0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
};
// lookup table for multiplication by 14 according to AES arithmetic
const uint8_t multBy14[] = {
0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
};

void encrypt(int encrypt, uint8_t plainText[], int textSize, uint8_t key[], uint8_t cipherText[]);
void cipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]);
void invCipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]);
void keyExpansion(const uint8_t inputKey[], uint8_t expandedKey[]);
void rotWord(uint8_t temp[]);
void subWord(uint8_t temp[]);
void xor(uint8_t *dest, const uint8_t *a, const uint8_t *b, int numBytes);
void addRoundKey(uint8_t state[4][4], uint8_t key[], int currRound);
void subBytes(uint8_t state[4][4]);
void shiftRows(uint8_t state[4][4]);
void mixColumns(uint8_t state[4][4]);
void invSubBytes(uint8_t state[4][4]);
void invShiftRows(uint8_t state[4][4]);
void invMixColumns(uint8_t state[4][4]);
void print(uint8_t plainText[], uint8_t textSize, uint8_t cipherText[]);
void printMsg(const char header[], uint8_t text[], uint8_t size);

void fatalError(const char *msg) {
    printf("fatal error: %s\n", msg);
    exit(1);
}

/*
 * aes() is the main interface to the aes cipher.  It breaks up the plain text
 * into 16 byte blocks and feeds each block to the main cipher routine.
 *
 * if encrypt == 1, then encrypt, else decrypt
 */
void encrypt(int encrypt, uint8_t plainText[], int textSize, uint8_t inputKey[], uint8_t cipherText[]) {
    uint8_t inBlock[BLOCK_SIZE];
    uint8_t outBlock[BLOCK_SIZE];
    uint8_t keySched[KEY_SCHED_SIZE];

    // create keySched
    keyExpansion(inputKey, keySched);

    // for each block of 128bits/16bytes, call cipher
    int i = 0;
    while (textSize > 0) {
        
        // if size of plaintext remaining is < BLOCK_SIZE, need to clear out block
        if (textSize < BLOCK_SIZE) {
            memset(inBlock, 0, BLOCK_SIZE);
        }

        memcpy(inBlock, plainText + i, BLOCK_SIZE);
        if (encrypt == 1)
            cipher(inBlock, outBlock, keySched);
        else
            invCipher(inBlock, outBlock, keySched);
        memcpy(cipherText + i, outBlock, BLOCK_SIZE);

        // increment i for next block
        i += BLOCK_SIZE;
        textSize -= BLOCK_SIZE;
    }
}
/*
 * this the main cipher routine that carries out the 10 rounds
 */
void cipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]) {
    uint8_t state[4][4];
    const int numRounds = 10;
    int currRound = 0;

    // copy input block to state array
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = inBlock[r + 4*c];
        }
    }

    DEBUG_CIPHER_STATE("initial state: ");

    addRoundKey(state, keySched, currRound);
    DEBUG_CIPHER_STATE("start of round 1: ");

    for (currRound = 1; currRound < numRounds; currRound++) {

        subBytes(state);
        DEBUG_CIPHER_STATE("after subBytes: ");

        shiftRows(state);
        DEBUG_CIPHER_STATE("after shiftRows: ");

        mixColumns(state);
        DEBUG_CIPHER_STATE("after mixColumns: ");

        addRoundKey(state, keySched, currRound);
        DEBUG_CIPHER_STATE("after addRoundKey: ");
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, keySched, currRound);

    DEBUG_CIPHER_STATE("end: ");

    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            outBlock[c*4+r] = state[r][c];
        }
    }
}

/*
 * this is the cipher inverse routine used for decrypting
 */
void invCipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]) {
    uint8_t state[4][4];
    int currRound = 10;     // start at round 10 and count down thru the key sched
 
    // copy input block to state array
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = inBlock[r + 4*c];
        }
    }

    addRoundKey(state, keySched, currRound);
    for (currRound = 9; currRound >= 1; currRound--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, keySched, currRound);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, keySched, currRound);

    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            outBlock[c*4+r] = state[r][c];
        }
    }  
}
void addRoundKey(uint8_t state[4][4], uint8_t key[], int currRound) {
    int Nb = 16;         // number of bytes in block
    int l = currRound * Nb;

    for (int c = 0; c < 4; c++) {
        state[0][c] = state[0][c] ^ key[l + c*4 + 0];
        state[1][c] = state[1][c] ^ key[l + c*4 + 1];
        state[2][c] = state[2][c] ^ key[l + c*4 + 2];
        state[3][c] = state[3][c] ^ key[l + c*4 + 3];
    }
}
/*
 * substitute bytes using S-Box
 */
void subBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = sBox[state[r][c]];
        }
    }
}
/*
 * sybstitute bytes using inverse S-Box
 */
void invSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = invSBox[state[r][c]];
        }
    }
}
/*
 * left shift the last 3 rows of the state block
 */
void shiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // left shift 2nd row 1 position
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // left shift 3rd row 2 positions
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // left shift 4th row 3 positions
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}
/*
 * inverse of shiftRows, right shift last 3 rows
 */
void invShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // right shift 2nd row 1 position
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // right shift 3rd row 2 positions
    temp = state[2][3];
    state[2][3] = state[2][1];
    state[2][1] = temp;
    temp = state[2][2];
    state[2][2] = state[2][0];
    state[2][0] = temp;

    // right shift 4th row 3 positions
    temp = state[3][3];
    state[3][3] = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = temp;
}
/*
 * AES multiplication in finite field GF(2^8):
 * say A = (a7a6..a0) and B = (b7b6..b0), 
 * then 0x02 * A equals (a6..a00) if a7 == 0
 * else it equals ((a6..a00) XOR 0x1b) if a7 == 1.
 */
uint8_t multByTwo(uint8_t x) {
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}
/*
 * Per Stalling's text: 0x03 * s = s ^ (0x02 * s)
 */
void mixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int c = 0; c < 4; c++) {
        temp[0] = state[0][c];
        temp[1] = state[1][c];
        temp[2] = state[2][c];
        temp[3] = state[3][c];
        //state[0][c] = multBy2[temp[0]]^multBy3[temp[1]]^temp[2]^temp[3];
        state[0][c] = multByTwo(temp[0])^temp[1]^multByTwo(temp[1])^temp[2]^temp[3];
        //state[1][c] = temp[0]^multBy2[temp[1]]^multBy3[temp[2]]^temp[3];
        state[1][c] = temp[0]^multByTwo(temp[1])^temp[2]^multByTwo(temp[2])^temp[3];
        state[2][c] = temp[0]^temp[1]^multByTwo(temp[2])^temp[3]^multByTwo(temp[3]);
        state[3][c] = temp[0]^multByTwo(temp[0])^temp[1]^temp[2]^multByTwo(temp[3]);
    }
    /*
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for(i = 0; i < 4; ++i)
  {  
    t   = state[i][0];
    Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ;
    Tm  = state[i][0] ^ state[i][1] ; Tm = xtime(Tm);  state[i][0] ^= Tm ^ Tmp ;
    Tm  = state[i][1] ^ state[i][2] ; Tm = xtime(Tm);  state[i][1] ^= Tm ^ Tmp ;
    Tm  = state[i][2] ^ state[i][3] ; Tm = xtime(Tm);  state[i][2] ^= Tm ^ Tmp ;
    Tm  = state[i][3] ^ t ;        Tm = xtime(Tm);  state[i][3] ^= Tm ^ Tmp ;
  }
    */
}
void invMixColumns(uint8_t state[4][4]) {
/*
    uint8_t temp[4];
    
    for (int c = 0; c < 4; c++) {
        temp[0] = state[0][c];
        temp[1] = state[1][c];
        temp[2] = state[2][c];
        temp[3] = state[3][c];
        state[0][c] = multBy14[temp[0]]^multBy11[temp[1]]^multBy13[temp[2]]^multBy9[temp[3]];
        state[1][c] = multBy9[temp[0]]^multBy14[temp[1]]^multBy11[temp[2]]^multBy13[temp[3]];
        state[2][c] = multBy13[temp[0]]^multBy9[temp[1]]^multBy14[temp[2]]^multBy11[temp[3]];
        state[3][c] = multBy11[temp[0]]^multBy13[temp[1]]^multBy9[temp[2]]^multBy14[temp[3]];
    }
*/
  int i;
  uint8_t a,b,c,d;
  for(i=0;i<4;++i)
  { 
    a = state[0][i];
    b = state[1][i];
    c = state[2][i];
    d = state[3][i];

    state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}
/*
 * based on pseudo code from Stallings text
 * inputKey is assumed to be of 16 bytes
 * expandedKey is assumed to be of 44 * 4 = 176 bytes
 */
void keyExpansion(const uint8_t inputKey[], uint8_t expandedKey[]) {
    uint8_t temp[4];

    // copy given key as is into beginning of expanded key
    memcpy(expandedKey, inputKey, 16);

    for (int i = 0; i < 4; i++) {
        DEBUG_KEY("key word %d: %02x%02x%02x%02x \n", i,
                expandedKey[i*4], expandedKey[i*4+1],
                expandedKey[i*4+2], expandedKey[i*4+3]);
    }

    for (int i = 4; i < 44; i++) {
        memcpy(temp, expandedKey + (4*i - 4), 4);
        
        if (i % 4 == 0) {
            // from the text:  temp = subWord(rotWord(temp)) XOR Rcon[i/4];
            rotWord(temp);
            subWord(temp);
            DEBUG_KEY("after subWord: %02x%02x%02x%02x ", temp[0],temp[1],temp[2],temp[3]);
            xor(temp, temp, &rcon[i/4], 1);
            DEBUG_KEY("after xor with rcon: %02x%02x%02x%02x ", temp[0],temp[1],temp[2],temp[3]);
        }

        // from the text:  w[i] = w[i-4] XOR temp
        xor(expandedKey + (4*i), expandedKey + ((4*i) - 16), temp, 4);

        DEBUG_KEY("key word %d: %02x%02x%02x%02x \n", i,
                expandedKey[i*4], expandedKey[i*4+1],
                expandedKey[i*4+2], expandedKey[i*4+3]);
    }
}

/*
 * perform byte substitution on each byte using S-box
 */
void subWord(uint8_t temp[]) {
    temp[0] = sBox[temp[0]];
    temp[1] = sBox[temp[1]];
    temp[2] = sBox[temp[2]];
    temp[3] = sBox[temp[3]];
}
/*
 * perform one-byte circular left shift on a word
 * i.e. [b0, b1, b2, b3] becomes [b1, b2, b3, b0]
 */
void rotWord(uint8_t temp[]) {
    uint8_t b0 = temp[0];
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = b0;
}

/*
 * dest = a XOR b
 * where numBytes = the number of bytes of a and b to XOR
 */
void xor(uint8_t *dest, const uint8_t *a, const uint8_t *b, int numBytes) {
    for (int i = 0; i < numBytes; i++) {
        dest[i] = a[i] ^ b[i];
    }
}

void test3() {
    uint8_t plainText[] = "Hello everyone, this is my very first secret message \
                           to you and I will encrypt it using the aes cipher.";
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x03, 0x01, 0x05, 0x02, 0x0f, 0x0a, 0x09, 0x07,
                     0x0a, 0x09, 0x08, 0x0b, 0x03, 0x0c, 0x0e, 0x0d};
    uint8_t cipherText[textSize];
    encrypt(1, plainText, textSize, key, cipherText);
    print(plainText, textSize, cipherText);

    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText);
    printMsg("decrypted: \n", decryptedText, textSize);
}
void test2() {
    uint8_t plainText[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t cipherText[textSize];
    encrypt(1, plainText, textSize, key, cipherText);

    print(plainText, textSize, cipherText);

    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText);
    printMsg("decrypted: \n", decryptedText, textSize);
}
void test1() {
    uint8_t plainText[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t cipherText[textSize];
    encrypt(1, plainText, textSize, key, cipherText);

    print(plainText, textSize, cipherText);

    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText);

    printMsg("decrypted: \n", decryptedText, textSize);
}

void printMsg(const char header[], uint8_t text[], uint8_t size) {
    printf("%s", header);
    for (int i = 0; i < size; i++) {
        if (i>0 && i%16 == 0) printf("\n");
        printf("%02x ", text[i]);
    }
    printf("\n");
}
void print(uint8_t plainText[], uint8_t textSize, uint8_t cipherText[]) {
    printf("plaintext: \n");
    for (int i = 0; i < textSize; i++) {
        if (i>0 && i%16 == 0) printf("\n");
        printf("%02x ", plainText[i]);
    }
    printf("\n");
    printf("ciphertxt: \n");
    for (int i = 0; i < textSize; i++) {
        if (i>0 && i%16 == 0) printf("\n");
        printf("%02x ", cipherText[i]);
    }
    printf("\n");
}

int main() {
    //printf("test1:\n");
    test1();

    //printf("test2:\n");
    //test2();

    //printf("test3:\n");
    //test3();

    return 0;
}
