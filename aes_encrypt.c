#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#define B_MOD 281
#define N_MOD 17

typedef char byte;  // 8-Bits
typedef int word;   // 4-Bytes

byte rcon[] = {};

byte sbox[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
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
                  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
// CIPHER
void sub_bytes(byte state[4][4]);
void shift_rows(byte state[4][4]);
void mix_columns(byte state[4][4]);
void add_round_key(byte state[4][4], byte w[4][4]);
void cipher(byte *a, byte *b, int ws, byte w[ws][4][4], int Nr);

// KEY GENERATION
void sub_word(byte *tren);
void rot_word(byte *tren);
void key_expansion(int ws, byte w[ws][4][4], byte *key, int Nk, int Nb, int Nr);

// GENERAL
FILE *safe_fopen(char *file, char *opt);
void print_usage();
void kill();

// INPUT PROCESSING
void read_cli(int argc, char **argv, FILE **in, FILE **out, FILE **key);
void read_key(FILE *kf, byte *key, int *key_size);
void encrypt_file(FILE *in, FILE *out, int ws, byte w[ws][4][4], int Nr);

int main (int argc, char **argv) {
    FILE *in = NULL;    // Input text file.
    FILE *out = NULL;   // Output text file.
    FILE *kf = NULL;    // Text file containing the key.

    // Read command line arguments and open respective files.
    read_cli(argc, argv, &in, &out, &kf);

    byte key[35];
    int Nr, Nb = 4, Nk;

    read_key(kf, key, &Nk);
    
    Nr = Nb + Nk + 2;
    int ws = Nb * (Nr + 1);
    byte w[ws][4][4];

    key_expansion(ws, w, key, Nk, Nb, Nr);

    encrypt_file(in, out, ws, w, Nr);

    fclose(in);
    fclose(out);
    fclose(kf);
    return 0;
}

FILE *safe_fopen(char *file, char *opt) {
    FILE *ret = fopen(file, opt);

    if (ret == NULL) {
        fprintf(stderr, "Could not open file %s\n", file);
        kill();
    }

    return ret;
}

void read_cli(int argc, char **argv, FILE **in, FILE **out, FILE **key) {
    int option;
    int iflag = 0, oflag = 0, kflag = 0, sflag = 0;
    while ((option = getopt(argc, argv, "i:o:k:s:")) != -1) {
        switch (option) {
            case 'i':
                // Input file option specified.
                if (iflag) {
                    fprintf(stderr, "Only one input file may be specified.\n");
                    kill();
                }
                iflag = 1;
                *in = safe_fopen(optarg, "r");
                break;
            case 'o':
                // Output file option specified.
                if (oflag) {
                    fprintf(stderr, "Only one output file may be specified.\n");
                    kill();
                }
                oflag = 1;
                *out = safe_fopen(optarg, "w");
                break;
            case 'k':
                // Key file option specified.
                if (kflag) {
                    fprintf(stderr, "Only one key file may be specified.\n");
                    kill();
                }
                kflag = 1;
                *key = safe_fopen(optarg, "r");
                break;
            case 's':
                printf("-s KEY_SIZE\n");
                break;
        }
    }
    // One of the input files was not specified.
    if (!iflag || !oflag || !kflag) {
        fprintf(stderr, "All three files must be specified.\n");
        kill();
    }
}

void print_usage() {
    printf("USAGE: ./enc -i INPUT_FILE -o OUTPUT_FILE -k KEY_FILE\n");
}

void kill() {
    print_usage();
    exit(EXIT_FAILURE);
}

void rot_word(byte *tren) {
    byte temp = tren[3];
    tren[3] = tren[0];
    tren[0] = tren[1];
    tren[1] = tren[2];
    tren[3] = temp;
}

void sub_word(byte *tren) {
    for (int i = 0; i < 4; ++i) {
        tren[i] = sbox[tren[i]];
    }
}

void key_expansion(int ws, byte w[ws][4][4], byte *key, int Nk, int Nb, int Nr) {
    int i = 0;
    int m = 0, r = 0;
    int klen = Nk;
    for (; i < klen; ++i) {
        w[m][r][0] = key[4 * i    ];
        w[m][r][1] = key[4 * i + 1];
        w[m][r][2] = key[4 * i + 2];
        w[m][r][3] = key[4 * i + 3];
            
        r++;
        if (r == 4) {
            r = 0;
            m++;
        }
    }

    klen = Nb * (Nr + 1);
    byte tren[4];
    int pm, pr;
    int bm, br;
    for (; i < klen; ++i) {
        pr = r - 1;
        pm = m;
        if (pr < 0) {
            pr = 3;
            pm = m - 1;
        }
        br = (i + Nk) % 4;
        bm = (Nk == 8) ? m - 2 : m - 1;
        
        tren[0] = w[pm][pr][0];
        tren[1] = w[pm][pr][1];
        tren[2] = w[pm][pr][2];
        tren[3] = w[pm][pr][3];

        if (i % Nk == 0) {
            rot_word(tren);
            sub_word(tren);

            tren[0] ^= (2ULL << i - 1) % B_MOD;
        }
        else if (Nk > 6 && i % Nk == 4) {
            sub_word(tren);
        }

        w[m][r][0] = w[bm][br][0] ^ tren[0];
        w[m][r][1] = w[bm][br][1] ^ tren[1];
        w[m][r][2] = w[bm][br][2] ^ tren[2];
        w[m][r][3] = w[bm][br][3] ^ tren[3];

        r++;
        if (r == 4) {
            r = 0;
            m++;
        }
    }
}

void sub_bytes(byte state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

void shift_rows(byte state[4][4]) {
    byte temp[4][4];
    memcpy(temp, state, 16);
    for (int i = 1; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][(j + 4 - i) % 4] = temp[i][j];
        }
    }
}

void mix_columns(byte state[4][4]) {
    byte temp[4][4];
    memcpy(temp, state, 16);
    for (int j = 0; j < 4; ++j) {
        state[0][j] = ((2 * temp[0][j]) % N_MOD) ^ ((3 * temp[1][j]) % N_MOD) ^ temp[2][j] ^ temp[3][j];
        state[1][j] = temp[0][j] ^ ((2 * temp[1][j]) % N_MOD) ^ ((3 * temp[2][j]) % N_MOD) ^ temp[3][j];
        state[2][j] = temp[0][j] ^ temp[1][j] ^ ((2 * temp[2][j]) % N_MOD) ^ ((3 * temp[3][j]) % N_MOD);
        state[3][j] = ((4 * temp[0][j]) % N_MOD) ^ temp[1][j] ^ temp[2][j] ^ ((2 * temp[3][j]) % N_MOD);
    }
}

void add_round_key(byte state[4][4], byte w[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] ^= w[i][j];
        }
    }
}

void cipher(byte *a, byte *b, int ws, byte w[ws][4][4], int Nr) {
    
    byte state[4][4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = a[j * 4 + i];
        }
    }

    add_round_key(state, w[0]);
    
    for (int round = 1; round < Nr; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, w[round]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, w[Nr]);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            b[j * 4 + i] = state[i][j];
        }
    }
}

void read_key(FILE *kf, byte *key, int *key_size) {
    fgets(key, 35, kf);
    
    *key_size = strlen(key) / 4;
    switch (*key_size) {
        case 4:
            printf("128-bit key.\n");
            break;
        case 6:
            printf("192-bit key.\n");
            break;
        case 8:
            printf("256-bit key.\n");
            break;
        default:
            fprintf(stderr, "The key must be 128, 192 or 256 bits long.\n");
            kill();
            break;
    }
}

void encrypt_file(FILE *in, FILE *out, int ws, byte w[ws][4][4], int Nr) {
    byte block[16];
    byte enc[16];
    while (!feof(in)) {
        fgets(block, 16, in);
        cipher(block, enc, ws, w, Nr);
        fputs(enc, out);
    }
}