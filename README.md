# AES
Advanced Encryption Standard

## Introduction
A library for encrypting/ decrypting strings(character arrays) or files using the Advanced Encryption Standard, a subset of the Rijndael block cipher, with a 128bit block size and supporting 128bit, 192bit and 256bit key lengths. 128bit key ciphers are announced sufficient for protecting classified information up to the SECRET level by the US government. TOP SECRET information will require use of the 192bit or 256bit key lengths. 

## Usage
```c
int set_key(unsigned char *_key, int _keylen);
```
Sets `_key` as the new cipher key.

```c
int generate_key(int _keylen);
```
Generates a new pseudo-random cipher key of length `_keylen`.

Key length must be 16(128bit), 24(192bit) or 32(256bit) characters.

### Encryption
```c
void cipher(unsigned char *_dest, unsigned char *_src, int _size);
```
Encrypts `_src` of length `_size` and writes the ciphertext to `_dest`. Size of `_dest` should be the nearest multiple of 16 greater than `_size`.

```c
void fcipher(FILE *_in, FILE *_out);
```
Reads 16 characters at a time from `_in`, ciphering them and writing to `_out`.

### Decryption
```c
void decipher(unsigned char *_dest, unsigned char *_src, int _size);
```
Decrypts `_src` of length `_size` and writes the ciphertext to `_dest`(should be the same size as `_src`).

```c
void fdecipher(FILE *_in, FILE *_out);
```
Reads 16 characters at a time from `_in`, deciphering them and writing to `_out`.

## Useful Links
* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
* http://www.angelfire.com/biz7/atleast/mix_columns.pdf
* https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
* https://en.wikipedia.org/wiki/Finite_field_arithmetic
* https://www.youtube.com/watch?v=x1v2tX4_dkQ
* https://www.youtube.com/watch?v=NHuibtoL_qk
