/*
 * DESL
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
  randomSeed(analogRead(0));
 }

 unsigned long time = 0;
 unsigned long cipherDuration = 0;
 unsigned long invCipherDuration = 0;
 unsigned long simTextSize = 0;

 void loop() {
  Serial.println("========== start DESL =======================");

  cipherDuration = 0;
  invCipherDuration = 0;
  
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

  Serial.print("text size: ");
  Serial.println(simTextSize);

  for (int i = 0; i < simTextSize / 8; i++) {
    forwardCipher();
  }
  for (int i = 0; i < simTextSize / 8; i++) {
    inverseCipher();
  }

  Serial.println();
  Serial.println("forward cipher duration (in milliseconds): ");
  Serial.println(cipherDuration);
  Serial.println("inverse cipher duration (in milliseconds): ");
  Serial.println(invCipherDuration);

  // turn the LED off to signal end of test
  digitalWrite(LED_BUILTIN, LOW);

  // delay(10000);
 }
#include <stdio.h>      // printf
#include <string.h>     // memset
#include <stdint.h>     // uint8_t

/*
 * DESL uses a single S-Box
 */
const uint8_t sBox[] = {
    14, 5, 7, 2, 11, 8, 1, 15, 0, 10, 9, 4, 6, 13, 12, 3,
    5, 0, 8, 15, 14, 3, 2, 12, 11, 7, 6, 9, 13, 4, 1, 10,
    4, 9, 2, 14, 8, 7, 13, 0, 10, 12, 15, 1, 5, 11, 3, 6,
    9, 6, 15, 5, 3, 8, 4, 11, 7, 1, 12, 2, 0, 14, 10, 13
};
/*
 * E bit-selection table
 */
const uint8_t message_expansion[] = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};
/*
 * permutation function P
 */
const uint8_t p[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};
/* 
 * Permuted choice 1 - table used in Key Schedule
 */
const uint8_t pc1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};
/*
 * Permuted choice 2 - table used in Key Schedule
 */
const uint8_t pc2[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
/*
 * left shifts in key schedule
 */
const uint8_t leftShifts[] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

#define BLOCK_SIZE 8
#define NUM_ROUNDS 16
#define BITS_IN_ROUND_KEY 48
#define BITS_IN_EXPANDED_KEY (BITS_IN_ROUND_KEY * NUM_ROUNDS)
#define ENCRYPTION_MODE 0
#define DECRYPTION_MODE 1

void process(uint8_t mode, uint8_t plainText[], int textSize, uint8_t inputKey[], uint8_t cipherText[]);
void cipher(uint8_t mode, uint8_t inBlock[8], uint8_t outBlock[8], uint8_t keySched[]);
void f(uint8_t r[4], uint8_t k[6], uint8_t out[4]);
void keyExpansion(const uint8_t inputKey[], uint8_t keySchedule[]);
void shift28Left(uint8_t c[]);
void printInHex(char header[], uint8_t arr[], uint8_t size);

/*
 * This is the main interface to the cipher.  It breaks up the plain text into 
 * 64-bit blocks and feeds each block to the cipher routine.
 *
 * inputKey - expected to be 64 bits
 */
void process(uint8_t mode, uint8_t plainText[], int textSize, uint8_t inputKey[], uint8_t cipherText[]) {
    uint8_t inBlock[BLOCK_SIZE];
    uint8_t outBlock[BLOCK_SIZE];
    uint8_t keySched[BITS_IN_EXPANDED_KEY];

    keyExpansion(inputKey, keySched);

    // for each 64-bit block, call cipher
    int i = 0;
    while (textSize > 0) {
        // if size of plaintext remaining is < BLOCK_SIZE, need to clear out block
        if (textSize < BLOCK_SIZE) {
            memset(inBlock, 0, BLOCK_SIZE);
        }

        // copy a 64-bit block from main msg
        memcpy(inBlock, plainText + i, BLOCK_SIZE);

        // give 64-bit block to cipher to encrypt/decrypt
        cipher(mode, inBlock, outBlock, keySched);

        // get back encrypted/decrypted block 
        memcpy(cipherText + i, outBlock, BLOCK_SIZE);

        // increment i for next block
        i += BLOCK_SIZE;
        textSize -= BLOCK_SIZE;
    }
}
 /*
  * This is the main cipher routine that carries out the 16 rounds
  * on a single 64-bit block
  */
void cipher(uint8_t mode, uint8_t inBlock[8], uint8_t outBlock[8], uint8_t keySched[]) {
    uint8_t l[4], r[4], tmp[4];
    uint8_t keyIndex;
    
    // split 64-bit plain text into l and r
    memcpy(l, inBlock, 4);
    memcpy(r, inBlock + 4, 4);
    //l[0] = inBlock[0], l[1] = inBlock[1], l[2] = inBlock[2], l[3] = inBlock[3];
    //r[0] = inBlock[4], r[1] = inBlock[5], r[2] = inBlock[6], r[3] = inBlock[7];

    for (int round = 0; round < 16; round++) {
        if (mode == ENCRYPTION_MODE) 
            keyIndex = round * (BITS_IN_ROUND_KEY / 8);
        else
            keyIndex = (15 - round) * (BITS_IN_ROUND_KEY / 8);
                
        // run f function
        f(r, keySched + keyIndex, tmp);

        for (int i = 0; i < 4; i++)
            l[i] ^= tmp[i];

        // swap r and l
        memcpy(tmp, r, 4);
        memcpy(r, l, 4);
        memcpy(l, tmp, 4);
    }
}

/*
 * The f function takes a 32-bit block (r) and a 48-bit key (k)
 * and produces 32-bit output (out).
 * reuses some code from:
 * https://github.com/tarequeh/DES/blob/master/des.c
 */
void f(uint8_t r[4], uint8_t k[6], uint8_t out[4]) {
    uint8_t shiftSize, shiftByte;
    uint8_t er[6];
    uint8_t ser[4];
    
    for (int i = 0; i < 48; i++) {
            shiftSize = message_expansion[i];
            shiftByte = 0x80 >> ((shiftSize - 1)%8);
            shiftByte &= r[(shiftSize - 1)/8];
            shiftByte <<= ((shiftSize - 1)%8);

            er[i/8] |= (shiftByte >> i%8);
    }
    for (int i = 0; i < 6; i++) {
        er[i] ^= k[i];
    }

    uint8_t row, column;
    memset(ser, 0, 4);

    // Byte 1
    row = 0;
    row |= ((er[0] & 0x80) >> 6);
    row |= ((er[0] & 0x04) >> 2);

    column = 0;
    column |= ((er[0] & 0x78) >> 3);

    ser[0] |= (sBox[row*16+column] << 4);

    row = 0;
    row |= (er[0] & 0x02);
    row |= ((er[1] & 0x10) >> 4);

    column = 0;
    column |= ((er[0] & 0x01) << 3);
    column |= ((er[1] & 0xE0) >> 5);

    ser[0] |= sBox[row*16+column];

    // Byte 2
    row = 0;
    row |= ((er[1] & 0x08) >> 2);
    row |= ((er[2] & 0x40) >> 6);

    column = 0;
    column |= ((er[1] & 0x07) << 1);
    column |= ((er[2] & 0x80) >> 7);

    ser[1] |= (sBox[row*16+column] << 4);

    row = 0;
    row |= ((er[2] & 0x20) >> 4);
    row |= (er[2] & 0x01);

    column = 0;
    column |= ((er[2] & 0x1E) >> 1);

    ser[1] |= sBox[row*16+column];

    // Byte 3
    row = 0;
    row |= ((er[3] & 0x80) >> 6);
    row |= ((er[3] & 0x04) >> 2);

    column = 0;
    column |= ((er[3] & 0x78) >> 3);

    ser[2] |= (sBox[row*16+column] << 4);

    row = 0;
    row |= (er[3] & 0x02);
    row |= ((er[4] & 0x10) >> 4);

    column = 0;
    column |= ((er[3] & 0x01) << 3);
    column |= ((er[4] & 0xE0) >> 5);

    ser[2] |= sBox[row*16+column];

    // Byte 4
    row = 0;
    row |= ((er[4] & 0x08) >> 2);
    row |= ((er[5] & 0x40) >> 6);

    column = 0;
    column |= ((er[4] & 0x07) << 1);
    column |= ((er[5] & 0x80) >> 7);

    ser[3] |= (sBox[row*16+column] << 4);

    row = 0;
    row |= ((er[5] & 0x20) >> 4);
    row |= (er[5] & 0x01);

    column = 0;
    column |= ((er[5] & 0x1E) >> 1);

    ser[3] |= sBox[row*16+column];

    memset(out, 0, 4);
    for (int i = 0; i < 32; i++) {
        shiftSize = p[i];
        shiftByte = 0x80 >> ((shiftSize - 1)%8);
        shiftByte &= ser[(shiftSize - 1)/8];
        shiftByte <<= ((shiftSize - 1)%8);

        out[i/8] |= (shiftByte >> i%8);
    }
}
/*
 * The key expansion function expects the original 64-bit key and expands it to:
 *   (# bits in each round's key) * (# rounds) = 48 * 16 = 768 bits
 */
void keyExpansion(const uint8_t inputKey[], uint8_t keySchedule[]) {
    uint8_t cd[7], c[4], d[4];  // temp storage used for convenience
    int8_t shiftSize;           // shift size can be negative
    uint8_t shiftByte;

    memset(cd, 0, 7);
    memset(c, 0, 4);
    memset(d, 0, 4);
    memset(keySchedule, 0, BITS_IN_EXPANDED_KEY / 8);

    // Permuted Choice 1
    for (int i = 0; i < 56; i++) {

        // pc1 table specifies bits from 1 - 64, so we minus 1
        uint8_t pc1value = pc1[i] - 1;

        // get the byte from the key where the pc1 bit falls
        shiftByte = inputKey[pc1value / 8];

        // find the number of places to shift
        shiftSize = (pc1value % 8) - (i % 8);

        // shift the byte to move the desired bit to the right place
        if (shiftSize > 0)
            shiftByte <<= shiftSize;
        else if (shiftSize < 0)
            shiftByte >>= (shiftSize * -1);

        // zero out the non-desired bits
        shiftByte &= (0x80 >> (i%8));

        // save that bit
        cd[i/8] |= shiftByte;
    }

    /*
     * the DES standard uses variables c and d, we do the same here for readability
     * move 56 bits out of cd[]
     * first 28 bits into c[], next 28 bits into d[]
     */
    c[0] = cd[0];
    c[1] = cd[1];
    c[2] = cd[2];
    c[3] = cd[3] & 0xf0;
    d[0] = cd[3] << 4;
    d[0] |= cd[4] >> 4;
    d[1] = cd[4] << 4;
    d[1] |= cd[5] >> 4;
    d[2] = cd[5] << 4;
    d[2] |= cd[6] >> 4;
    d[3] = cd[6] << 4;

    for (int round = 0; round < NUM_ROUNDS; round++) {

        // left shifts
        for (int i = 0; i < leftShifts[round]; i++) {
            shift28Left(c);
            shift28Left(d);
        }

        // copy c[] and d[] back to cd[] to make PC2 step easy
        cd[0] = c[0];
        cd[1] = c[1];
        cd[2] = c[2];
        cd[3] = c[3];
        cd[3] |= d[0] >> 4;
        cd[4] = d[0] << 4;
        cd[4] |= d[1] >> 4;
        cd[5] = d[1] << 4;
        cd[5] |= d[2] >> 4;
        cd[6] = d[2] << 4;
        cd[6] |= d[3] >> 4;

        // Permuted Choice 2 - similar to PC1 steps above
        uint8_t pc2value;
        for (int i = 0; i < 48; i++) {
            pc2value = pc2[i] - 1;
            shiftByte = cd[pc2value / 8];
            shiftSize = (pc2value % 8) - (i % 8);
            if (shiftSize > 0)
                shiftByte <<= shiftSize;
            else if (shiftSize < 0)
                shiftByte >>= (shiftSize * -1);
            shiftByte &= (0x80 >> (i%8));
            keySchedule[(i/8) + (round * BITS_IN_ROUND_KEY / 8)] |= shiftByte;
        }
    }
}
/*
 * Shift 28 (not 32) bits one bit to the left and carry
 * byte[] is expected to be 32 bits
 */
void shift28Left(uint8_t byte[]) {
    uint8_t tmp = 0x00;
    byte[3] &= 0xf0;
    for (int j = 3; j >= 0; j--) {
        tmp |= byte[j] & 0x80;
        byte[j] <<= 1;
        byte[j] |= tmp & 0x01;
        tmp >>= 7;
    }
    tmp <<= 4;
    byte[3] |= tmp & 0x10;
}
void printInHex(char header[], uint8_t arr[], uint8_t size) {
    printf("\n%s: ", header);
    for (uint8_t i = 0; i < size; i++) {
        printf(" %02x", arr[i]);
    }
    printf("\n");
}
void forwardCipher() {
    uint8_t plainText[8];
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    for (int i = 0; i < textSize; i++) {
      plainText[i] = random(256);
    }
    uint8_t key[8];
    for (int i = 0; i < 8; i++) {
      key[i] = random(256);
    }
    
    uint8_t cipherText[textSize];

    time = millis();
    process(ENCRYPTION_MODE, plainText, textSize, key, cipherText);
    cipherDuration += millis() - time;
}
void inverseCipher() {
    uint8_t plainText[8];
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key[8];
    for (int i = 0; i < 8; i++) {
      key[i] = random(256);
    }
   
    uint8_t cipherText[textSize];
    for (int i = 0; i < textSize; i++) {
      cipherText[i] = random(256);
    }

    time = millis();
    process(DECRYPTION_MODE, cipherText, textSize, key, plainText);
    invCipherDuration += millis() - time;
}
void test1() {
    uint8_t plainText[] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
    };
    int textSize = sizeof(plainText) / sizeof(plainText[0]);
    uint8_t key1[] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0xc0
    };
    uint8_t key2[] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    uint8_t cipherText[textSize];

    process(ENCRYPTION_MODE, plainText, textSize, key2, cipherText);

    process(DECRYPTION_MODE, cipherText, textSize, key2, plainText);
}

