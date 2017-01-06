#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


char* gen_key(size_t l)
{
    char *key = (char*) malloc(l);
    if (!key) {
        puts("Error, plz contact admin");
        exit(1);
    }

    gcry_randomize(key, l, GCRY_STRONG_RANDOM);

    return key;
}

void encrypt()
{

    size_t out_len = 600;

    char *key = gen_key(out_len);

    for (int i = 0; i < out_len; i++)
        printf("%02x", key[i] & 0xff);
    puts("");

    free(key);
    exit(0);
}


int main()
{

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);


    encrypt();

}

