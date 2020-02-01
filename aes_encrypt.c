#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

typedef char byte;
typedef int word;

void SubBytes();
void ShiftRows();
void MixColumns();
void AddRoundKey();
void Cipher();

FILE *safe_fopen(char *file, char *opt);
void read_cli(int argc, char **argv, FILE **in, FILE **out, FILE **key);
void print_usage();

int main (int argc, char **argv) {
    FILE *in = NULL;
    FILE *out = NULL;
    FILE *key = NULL;

    read_cli(argc, argv, &in, &out, &key);

    return 0;
}

FILE *safe_fopen(char *file, char *opt) {
    FILE *ret = fopen(file, opt);

    if (ret == NULL) {
        fprintf(stderr, "Could not open file %s\n", file);
        print_usage();
        exit(EXIT_FAILURE);
    }

    return ret;
}

void read_cli(int argc, char **argv, FILE **in, FILE **out, FILE **key) {
    int option;
    int iflag = 0, oflag = 0, kflag = 0, sflag = 0;
    while ((option = getopt(argc, argv, "i:o:k:s:")) != -1) {
        switch (option) {
            case 'i':
                if (iflag) {

                }
                iflag = 1;
                *in = safe_fopen(optarg, "r");
                break;
            case 'o':
                if (oflag) {

                }
                oflag = 1;
                *out = safe_fopen(optarg, "w");
                break;
            case 'k':
                if (kflag) {

                }
                kflag = 1;
                *key = safe_fopen(optarg, "r");
                break;
            case 's':
                printf("-s KEY_SIZE\n");
                break;
        }
    }
}

void print_usage() {
    printf("USAGE: ./enc -i INPUT_FILE -o OUTPUT_FILE -k KEY_FILE\n");
}
