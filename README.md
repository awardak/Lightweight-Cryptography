# Lightweight-Cryptography

This project contains my attempts at implementing and measuring the performace of cryptographic algorithms on resource constrained devices, specifically the [Arduino Uno Rev 3](https://www.arduino.cc/en/Main/ArduinoBoardUno) which has an 8-bit, 16 MHz microcontroller and only 2KB of [SRAM](https://www.arduino.cc/en/Tutorial/Memory).

The sketch_* folders have the sketch files that are used to load onto the Arduino.

### Results:
#### AES-128:
|Plaintext size|Forward cipher (in microseconds)|Inverse cipher (in microseconds)|
|-------------:|-------------------------------:|-------------------------------:|
|16 bytes      |820                             |1690                            |
|1 KB          |50,000                          |104,000                         |
|10 KB         |501,000                         |1,045,000                       |
|100 KB        |5,009,000                       |10,449,000                      |
|1 MB          |50,088,000                      |104,491,000                     |
*The times in the last four rows are rounded to the nearest millisecond.

### Resources:
- [AES Proposal: Rijndael](http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf)
- [FIPS 197: AES](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
- [AES Speed](https://cr.yp.to/aes-speed.html)
- [Block Cipher Modes of Operation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [The LED Block Cipher](https://sites.google.com/site/ledblockcipher/)
