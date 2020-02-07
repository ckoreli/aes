#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define MAX_KEYLEN 32
#define MAX_ROUND_KEYS
#define MUL_MOD 17

static const int Nb = 4;    // Block size(Nb x Nb).
static int Nr;              // Number of rounds to be performed on state.
static int Nk;              // Size of key in words.
static int Bk;              // Size of key in bytes.
static int ws;              // Number of key blocks.

static unsigned char key[MAX_KEYLEN];               // Base key.
static unsigned char w[MAX_ROUND_KEYS][Nb][Nb];     // Expanded key.
static unsigned char state[Nb][Nb];                 // Current state during encryption/ decryption.

// Sets key bytes to zero.
static void reset_key() {
    memset(key, 0, sizeof(key));
}

// Shifts word bytes once to the right.
void inv_rot_word(unsigned char *word) {
    unsigned char temp = word[3];
    word[3] = word[2];
    word[2] = word[1];
    word[1] = word[0];
    word[0] = temp;
}

// Shifts word bytes once to the left.
void rot_word(unsigned char *word) {
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// Substitues word bytes with s-box equivalent.
void sub_word(unsigned char *word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = s_box[word[i]];
    }
}

// Gets indices for (i-1)st and (i-Nk)th word.
static void get_indices(int m, int c, int *nm, int *nc, int d) {
    if (d == 1) {
        *nc = (c == 0) ? 3 : c - 1;
        *nm = (c == 0) ? m - 1: m;
    }
    else if (d == 4) {
        *nm = m - 1;
        *nc = c;
    }
    else if (d == 6) {
        *nc = (c + 2) % 4;
        *nm = (c > 1) ? m - 1: m - 2;
    }
    else if (d == 8) {
        *nm = m - 2;
        *nc = c;
    }
}

// Expands key.
static void key_expansion() {
    int m = 0;
    int i = 0;
    int c = 0;

    // First Nk words of the expanded key are the base key words.
    for (i = 0; i < Nk; ++i) {
        w[m][0][c] = key[4 * i    ];
        w[m][1][c] = key[4 * i + 1];
        w[m][2][c] = key[4 * i + 2];
        w[m][3][c] = key[4 * i + 3];

        // Move to the next word.
        ++c;
        if (c == 4) {
            c = 0;
            ++m;
        }
    }

    unsigned char temp[4];

    // Indices for the (i-1)st word and (i-Nk)th word.
    int pm, pc;
    int bm, bc;

    // Constructing the expanded key one word at a time.
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        // Get the indices of the (i-1)st word and (i-Nk)th word.
        gmc(m, c, &pm, &pc, 1);
        gmc(m, c, &bm, &bc, Nk);

        // (i-1)st word.
        temp[0] = w[pm][0][pc];
        temp[1] = w[pm][1][pc];
        temp[2] = w[pm][2][pc];
        temp[3] = w[pm][3][pc];

        // Mutations if its the Nk-th word.
        if (i % Nk == 0) {
            rot_word(temp);
            sub_word(temp);

            temp[0] = temp[0] ^ r_con[i / Nk];
        }
        // Special case for Nk == 8(256bit key). Substitue bytes if i + 4 is a multiple of Nk.
        else if (Nk > 6 && i % Nk == 4) {
            sub_word(temp);
        }

        // New word is mutated (i-1)st word XOR (i-Nk)th word.
        w[m][0][c] = temp[0] ^ w[bm][0][bc];
        w[m][1][c] = temp[1] ^ w[bm][1][bc];
        w[m][2][c] = temp[2] ^ w[bm][2][bc];
        w[m][3][c] = temp[3] ^ w[bm][3][bc];

        // Move to the next word.
        ++c;
        if (c == 4) {
            c = 0;
            ++m;
        }
    }
}

// Sets new cipher key. Rounds to nearest key size if too small.
int set_key(unsigned char *_key, int _keylen) {
    // Length of the key in bytes.
    Bk = _keylen;

    if (Bk > 32) {
        printf("Key is too long. Can be max 32 bytes(characters) long.\n");
        return -1;
    }

    // Setting global variables.
    Nk = Bk / 4;
    Nr = Nb + Nk + 2;
    ws = Nr + 1;

    // Copying key.
    reset_key();
    for (int i = 0; i < Bk; ++i) {
        key[i] = _key[i];
    }

    key_expansion();
}

// Generates random cipher key.
int generate_key(int _keylen) {
    if (_keylen != 128 && _keylen != 192 && _keylen != 256) {
        printf("Key must be 128, 192 or 256 bits.\n");
        return -1;
    }

    srand(time(NULL));

    // Setting global variables.
    Bk = _keylen / 8;
    Nk = Bk / 4;
    Nr = Nb + Nk + 2;
    ws = Nr + 1;

    // Generating pseudo random key.
    reset_key();
    for (int i = 0; i < Bk; ++i) {
        key[i] = (unsigned char)(rand() % 256);
    }

    key_expansion();
}

// Adds round key block to respective state.
static void add_round_key(int s) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] ^= w[s][i][j];
        }
    }
}

// Substitues state bytes with s-box equivalent.
static void sub_bytes() {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = s_box[state[i][j]];
        }
    }
}

// Shifts state rows i times to the left(where i represents the row counting from 0).
static void shift_rows() {
    for (int i = 1; i < 4; ++i) {
        for (int j = 0; j < i; ++j) {
            rot_word(state[i]);
        }
    }
}

// Matrix multiplication for mixing column values(obfuscation).
static void mix_columns() {
    unsigned char temp[4][4];
    memcpy(temp, state, sizeof(temp));

    for (int j = 0; j < 4; ++j) {
        state[0][j] = ((2 * temp[0][j]) % MUL_MOD) ^ ((3 * temp[1][j]) % MUL_MOD) ^ temp[2][j] ^ temp[3][j];
        state[1][j] = temp[0][j] ^ ((2 * temp[1][j]) % MUL_MOD) ^ ((3 * temp[2][j]) % MUL_MOD) ^ temp[3][j];
        state[2][j] = temp[0][j] ^ temp[1][j] ^ ((2 * temp[2][j]) % MUL_MOD) ^ ((3 * temp[3][j]) % MUL_MOD);
        state[3][j] = ((4 * temp[0][j]) % MUL_MOD) ^ temp[1][j] ^ temp[2][j] ^ ((2 * temp[3][j]) % MUL_MOD);
    }
}

// Encrypts string.
void cipher(unsigned char *_str, int _size) {

}

// Encrypts file.
void fcipher(FILE *in) {

}

// Substitues state bytes with inverse s-box equivalent.
static void inv_sub_bytes() {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = inv_s_box[state[i][j]];
        }
    }
}

// Shifts state rows i times to the right(where i is the row number counting from 0).
static void inv_shift_rows() {
    for (int i = 1; i < 4; ++i) {
        for (int j = 0; j < i; ++j) {
            inv_shift_rows(state[i]);
        }
    }
}

// Matrix multiplication for deobfuscation.
static void inv_mix_columns() {
    unsigned char temp[4][4];
    memcpy(temp, state, sizeof(temp));

    for (int j = 0; j < 4; ++j) {
        state[0][j] = ((0x0e * temp[0][j]) % MUL_MOD) ^ ((0x0b * temp[1][j]) % MUL_MOD) ^ ((0x0d * temp[2][j]) % MUL_MOD) ^ ((0x09 * temp[3][j]) % MUL_MOD);
        state[1][j] = ((0x09 * temp[0][j]) % MUL_MOD) ^ ((0x0e * temp[1][j]) % MUL_MOD) ^ ((0x0b * temp[2][j]) % MUL_MOD) ^ ((0x0d * temp[3][j]) % MUL_MOD);
        state[2][j] = ((0x0d * temp[0][j]) % MUL_MOD) ^ ((0x09 * temp[1][j]) % MUL_MOD) ^ ((0x0e * temp[2][j]) % MUL_MOD) ^ ((0x0b * temp[3][j]) % MUL_MOD);
        state[3][j] = ((0x0b * temp[0][j]) % MUL_MOD) ^ ((0x0d * temp[1][j]) % MUL_MOD) ^ ((0x09 * temp[2][j]) % MUL_MOD) ^ ((0x0e * temp[3][j]) % MUL_MOD);
    }
}

// Deciphers string.
void decipher(unsigned char *_str, int _size) {

}

// Deciphers file.
void fdecipher(FILE *in) {

}