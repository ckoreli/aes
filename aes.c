#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define MAX_KEYLEN 32
#define MAX_ROUND_KEYS 15
#define MUL_MOD 283
#define NB 4

static const int Nb = 4;    // Block size(Nb x Nb).
static int Nr;              // Number of rounds to be performed on state.
static int Nk;              // Size of key in words.
static int Bk;              // Size of key in bytes.
static int ws;              // Number of key blocks.

static unsigned char key[MAX_KEYLEN];               // Base key.
static unsigned char w[MAX_ROUND_KEYS][NB][NB];     // Expanded key.
static unsigned char state[NB][NB];                 // Current state during encryption/ decryption.

int min(int a, int b) {
    return (a < b) ? a : b;
}

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
        get_indices(m, c, &pm, &pc, 1);
        get_indices(m, c, &bm, &bc, Nk);

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

// Sets new cipher key.
int set_key(unsigned char *_key, int _keylen) {
    if (_keylen != 16 && _keylen != 24 && _keylen != 32) {
        printf("Key must be 128, 192 or 256 bits.\n");
        return -1;
    }
    // Length of the key in bytes.
    Bk = _keylen;

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
    return 0;
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
    return 0;
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

// Multiplying with 0x02 in GF(2^8).
unsigned char mul2(unsigned char a) {
    unsigned char p = (1 << 7);
    if (a >= p)
    {
        return (a << 1) ^ 0x1b;
    }
    return (a << 1);
}

// Multiplying with 0x03 in GF(2^8).
unsigned char mul3(unsigned char a) {
    return (mul2(a) ^ a);
}

// Matrix multiplication for mixing column values(obfuscation).
static void mix_columns() {
    unsigned char temp[4][4];
    memcpy(temp, state, sizeof(temp));

    for (int j = 0; j < 4; ++j) {
        state[0][j] = mul2(temp[0][j]) ^ mul3(temp[1][j]) ^ temp[2][j] ^ temp[3][j];
        state[1][j] = temp[0][j] ^ mul2(temp[1][j]) ^ mul3(temp[2][j]) ^ temp[3][j];
        state[2][j] = temp[0][j] ^ temp[1][j] ^ mul2(temp[2][j]) ^ mul3(temp[3][j]);
        state[3][j] = mul3(temp[0][j]) ^ temp[1][j] ^ temp[2][j] ^ mul2(temp[3][j]);
    }
}

static void pp(unsigned char x[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            if (x[j][i] < 16) {
                printf("0%x", x[j][i]);
            }
            else {
                printf("%x", x[j][i]);
            }
        }
    }
    printf("\n");
}

// Encrypts string one 16 byte block at a time.
void cipher(unsigned char *_dest, unsigned char *_src, int _size) {
    for (int i = 0; i < _size; i += 16) {
        memset(state, 0, sizeof(state));
        
        // Sets state to current 16 byte block.
        int r=0, c=0, l=min(i + 16, _size);
        for (int j = i; j < l; ++j) {
            state[r][c] = _src[j];

            ++r;
            if (r == 4) {
                r = 0;
                ++c;
            }
        }
        
        // Initialy adding round key.
        add_round_key(0);
        
        // Doing Nr-1 rounds.
        for (int round = 1; round < Nr; ++round) {
            sub_bytes();
            shift_rows();
            mix_columns();
            add_round_key(round);
        }

        // Final round.
        sub_bytes();
        shift_rows();
        add_round_key(Nr);
        
        // Copy final state to destination array.
        for (int j = 0; j < 4; ++j) {
            for (int k = 0; k < 4; ++k) {
                _dest[i + k * 4 + j] = state[j][k];
            }
        }
    }
}

// Encrypts file.
void fcipher(FILE *in, FILE *out) {

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
            inv_rot_word(state[i]);
        }
    }
}

// Multiplying with 0x0e in GF(2^8).
unsigned char mul0e(unsigned char a) {
    return (mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ mul2(a));
}

// Multiplying with 0x0b in GF(2^8).
unsigned char mul0b(unsigned char a) {
    return (mul2(mul2(mul2(a))) ^ mul2(a) ^ a);
}

// Multiplying with 0x0d in GF(2^8).
unsigned char mul0d(unsigned char a) {
    return (mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ a);
}

// Multiplying with 0x09 in GF(2^8).
unsigned char mul09(unsigned char a) {
    return (mul2(mul2(mul2(a))) ^ a);
}

// Matrix multiplication for deobfuscation.
static void inv_mix_columns() {
    unsigned char temp[4][4];
    memcpy(temp, state, sizeof(temp));

    for (int j = 0; j < 4; ++j) {
        state[0][j] = mul0e(temp[0][j]) ^ mul0b(temp[1][j]) ^ mul0d(temp[2][j]) ^ mul09(temp[3][j]);
        state[1][j] = mul09(temp[0][j]) ^ mul0e(temp[1][j]) ^ mul0b(temp[2][j]) ^ mul0d(temp[3][j]);
        state[2][j] = mul0d(temp[0][j]) ^ mul09(temp[1][j]) ^ mul0e(temp[2][j]) ^ mul0b(temp[3][j]);
        state[3][j] = mul0b(temp[0][j]) ^ mul0d(temp[1][j]) ^ mul09(temp[2][j]) ^ mul0e(temp[3][j]);
    }
}

// Deciphers string one 16 byte block at a time.
void decipher(unsigned char *_dest, unsigned char *_src, int _size) {
    for (int i = 0; i < _size; i += 16)
    {
        memset(state, 0, sizeof(state));

        //
        int r = 0, c = 0, l = min(i + 16, _size);
        for (int j = i; j < l; ++j)
        {
            state[r][c] = _src[j];

            ++r;
            if (r == 4)
            {
                r = 0;
                ++c;
            }
        }
        // Initialy adding round key.
        add_round_key(Nr);

        // Doing Nr-1 rounds.
        for (int round = Nr - 1; round > 0; --round) {
            inv_sub_bytes();
            inv_shift_rows();
            add_round_key(round);
            inv_mix_columns();
        }

        // Final round.
        inv_sub_bytes();
        inv_shift_rows();
        add_round_key(0);

        for (int j = 0; j < 4; ++j) {
            for (int k = 0; k < 4; ++k) {
                _dest[i + k * 4 + j] = state[j][k];
            }
        }
    }
}

// Deciphers file.
void fdecipher(FILE *in, FILE *out) {

}