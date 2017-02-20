/*
 * AES-128
 * author: Aman Wardak
 */

 void setup() {
  // initialize digital pin LED_BUILTIN as an output.
  pinMode(LED_BUILTIN, OUTPUT);
  
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
 }

 unsigned long time;
 unsigned long cipherDuration;
 unsigned long invCipherDuration;
 unsigned long simTextSize = 0;

 void loop() {
  Serial.println("========== start AES =======================");
  
  // turn the LED on to signal start of test
  digitalWrite(LED_BUILTIN, HIGH);    

  switch(simTextSize) {
    case 0:       simTextSize = 16;
                  break;
    case 16:      simTextSize = 1000;
                  break;
    case 1000:    simTextSize = 10000;
                  break;
    case 10000:   simTextSize = 100000;
                  break;
    case 100000:  simTextSize = 1000000;
                  break;
    case 1000000: simTextSize = 16;
                  break;
  }
  
  test1(simTextSize);

  Serial.println();
  Serial.println("forward cipher duration (in microseconds): ");
  Serial.println(cipherDuration);
  Serial.println("inverse cipher duration (in microseconds): ");
  Serial.println(invCipherDuration);

  // turn the LED off to signal end of test
  digitalWrite(LED_BUILTIN, LOW);

  // delay(10000);
 }

#include <stdio.h>      // printf
#include <stdlib.h>     // exit
#include <string.h>     // memcpy, memset
#include <stdint.h>     // uint8_t

// for debugging
#define DEBUG_KEY_FLAG 0
#define DEBUG_CIPHER_STATE_FLAG 0

#define DEBUG_KEY(a,b,c,d,e,f) do {         \
    if (DEBUG_KEY_FLAG) {                   \
        Serial.print(a);                    \
        Serial.print(b);                    \
        Serial.print(" -- ");               \
        Serial.print(c, HEX);               \
        Serial.print(d, HEX);               \
        Serial.print(e, HEX);               \
        Serial.println(f, HEX);             \
    }                                       \
} while(0)

#define DEBUG_CIPHER_STATE(a) do {          \
    if (DEBUG_CIPHER_STATE_FLAG) {          \
        for (int r=0; r<4; r++) {           \
          Serial.print(a);                  \
          Serial.print(state[r][0], HEX);   \
          Serial.print(state[r][1], HEX);   \
          Serial.print(state[r][2], HEX);   \
          Serial.println(state[r][3], HEX); \
        }                                   \
    }                                       \
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


void encrypt(int encrypt, uint8_t plainText[], int textSize, uint8_t key[], uint8_t cipherText[], unsigned long);
void cipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]);
void invCipher(uint8_t inBlock[16], uint8_t outBlock[16], uint8_t keySched[]);
void keyExpansion(const uint8_t inputKey[], uint8_t expandedKey[]);
void rotWord(uint8_t temp[]);
void subWord(uint8_t temp[]);
void xorBytes(uint8_t *dest, const uint8_t *a, const uint8_t *b, int numBytes);
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
 *
 * To simulate 1K, 10K, and 1M plain text sizes, we just run the cipher routine on
 * the same plaintext multiple times because the Arduino is limited to 2K of RAM so
 * we can't have real static data, and it's limited to 32K of flash memory
 * - int simCounter is the number of times to simulate the cipher, e.g. for plain
 * text size of 1000 bytes, simCounter = 1000 / 16 
 */
void encrypt(int encrypt, uint8_t plainText[], int textSize, uint8_t inputKey[], uint8_t cipherText[],
                unsigned long simCounter) {
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
        
        if (encrypt == 1) {
            time = micros();
            for (int counter = 0; counter < simCounter; counter++) {
                cipher(inBlock, outBlock, keySched);
            }
            cipherDuration = micros();
            cipherDuration = cipherDuration - time;
        }
        else {
            // micros() returns the total amount of microseconds the program has been running
            time = micros();
            for (int counter = 0; counter < simCounter; counter++) {
                invCipher(inBlock, outBlock, keySched);
            }
            invCipherDuration = micros();
            invCipherDuration = invCipherDuration - time;
        }
            
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

    DEBUG_CIPHER_STATE("after last round: ");

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
        state[0][c] = multByTwo(temp[0])^temp[1]^multByTwo(temp[1])^temp[2]^temp[3];
        // state[0][c] = multBy2[temp[0]]^multBy3[temp[1]]^temp[2]^temp[3];
        state[1][c] = temp[0]^multByTwo(temp[1])^temp[2]^multByTwo(temp[2])^temp[3];
        // state[1][c] = temp[0]^multBy2[temp[1]]^multBy3[temp[2]]^temp[3];
        state[2][c] = temp[0]^temp[1]^multByTwo(temp[2])^temp[3]^multByTwo(temp[3]);
        state[3][c] = temp[0]^multByTwo(temp[0])^temp[1]^temp[2]^multByTwo(temp[3]);
    }
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
        DEBUG_KEY("key word ", i,
                expandedKey[i*4], expandedKey[i*4+1],
                expandedKey[i*4+2], expandedKey[i*4+3]);
    }

    for (int i = 4; i < 44; i++) {
        memcpy(temp, expandedKey + (4*i - 4), 4);
        
        if (i % 4 == 0) {
            rotWord(temp);
            subWord(temp);
            DEBUG_KEY("after subWord ", i, temp[0],temp[1],temp[2],temp[3]);
            xorBytes(temp, temp, &rcon[i/4], 1);
            DEBUG_KEY("after xor with rcon ", i, temp[0],temp[1],temp[2],temp[3]);
        }

        xorBytes(expandedKey + (4*i), expandedKey + ((4*i) - 16), temp, 4);

        DEBUG_KEY("key word ", i,
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
void xorBytes(uint8_t *dest, const uint8_t *a, const uint8_t *b, int numBytes) {
    for (int i = 0; i < numBytes; i++) {
        dest[i] = a[i] ^ b[i];
    }
}

void test3() {
    uint8_t plainText[] = "Hello everyone, this is a very very secret message \
                           to you and I will encrypt it using the aes cipher.";
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x03, 0x01, 0x05, 0x02, 0x0f, 0x0a, 0x09, 0x07,
                     0x0a, 0x09, 0x08, 0x0b, 0x03, 0x0c, 0x0e, 0x0d};
    uint8_t cipherText[textSize];
    encrypt(1, plainText, textSize, key, cipherText, 1);
    print(plainText, textSize, cipherText);

    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText, 1);
    printMsg("decrypted: \n", decryptedText, textSize);
}
void test2() {
    Serial.println("Running test2()...\n");
    uint8_t plainText[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t cipherText[textSize];
    encrypt(1, plainText, textSize, key, cipherText, 1);

    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText, 1);

    arduinoPrint("plaintext before encryption: ", plainText, textSize);
    arduinoPrint("ciphertext after encryption: ", cipherText, textSize);
    arduinoPrint("text after decryption: ", decryptedText, textSize);
}
/*
 * simTextSize is the simulated size of plain text, e.g. simTextSize=1000
 * means we want to simulate the encryption on a text size of 1KB
 */
void test1(unsigned long simTextSize) {
    Serial.print("Running test on plain text size of: ");
    Serial.println(simTextSize);
    Serial.println();
    uint8_t plainText[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t cipherText[textSize];
    
    arduinoPrint("plaintext before encryption: ", plainText, textSize);
    
    unsigned long simCounter = simTextSize / 16;
    encrypt(1, plainText, textSize, key, cipherText, simCounter);
    arduinoPrint("ciphertext after encryption: ", cipherText, textSize);
    
    uint8_t decryptedText[16];
    encrypt(0, cipherText, textSize, key, decryptedText, simCounter);
    arduinoPrint("plaintext after decryption: ", decryptedText, textSize);
}
void arduinoPrint(const char header[], uint8_t msg[], int size) {
    Serial.println(header);
    for (int i = 0; i < size; i++) {
      Serial.print(msg[i], HEX);
      Serial.print(" ");
    }
    Serial.println();
}

