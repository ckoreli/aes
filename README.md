# AES
Advanced Encryption Standard

## Introduction
Perhaps the most popular encryption algorithm, AES(originaly called Rijndael) is a symmetric-key algorithm block cipher, meaning the same key is used for both encrypting and decrypting the data.

## Usage
### Encryption
```sh
./aes_encrypt -i INPUT_FILE -o OUTPUT_FILE -k KEY_FILE
```
* `-i` specifies the input text file on which the cipher will be implemented.
* `-o` specifies the file to which to write the cipher text.
* `-k` specifies a text file containing the encryption key(may be 128, 192 or 256 bits long).

### Decryption
```sh
./aes_decrypt -i INPUT_FILE -o OUTPUT_FILE -k KEY_FILE
```
* `-i` specifies the input text file which is to be deciphered.
* `-o` specifies the file to which to write the deciphered text.
* `-k` specifies a text file containing the encryption key(may be 128, 192 or 256 bits long).

## Useful Links
* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
* https://www.youtube.com/watch?v=x1v2tX4_dkQ
* https://www.youtube.com/watch?v=NHuibtoL_qk