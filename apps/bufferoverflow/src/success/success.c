#define LTM_DESC

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>

#include "libtomcrypt/src/headers/tomcrypt.h"

//system psuedo rng
#define PRNG "sprng"

//SHA-256
#define HASH "sha256"
#define BUFFER_SIZE 256


void setup_libtom();
void get_key(rsa_key* key);
char* build_ticket();

uint8_t* hexstring_to_bytes(char* hexstring, uint64_t char_count);
uint8_t hexchar_to_value(char c);

int main() {

//key should be a hexstring of the der key bytes
#ifndef KEY 
    printf("No key. Please contact an instructor or TA.\n");
    exit(1);
#endif

//keysize is the len of the key hexstring 
#ifndef KEYSIZE
    printf("No key size. Please contact an instructor or TA.\n");
    exit(1);
#endif

//string of the username
#ifndef USERNAME
    printf("No username set. Please contact an instructor or TA.\n");
    exit(1);
#endif

    //build a ticket, ticket is a string in the format "<username>:<time ns since epoch>"
    char* ticket = build_ticket();

    //setup stuff for libtommath and libtomcrypt for the RSA encryption
    setup_libtom();

    //turn the KEY into a rsa_key obect
    rsa_key key;
    get_key(&key);
    
    //make sure the rsa_key parsed properly
    int keysizebytes = rsa_get_size(&key);
    if (keysizebytes == INT_MAX) {
        printf("Error getting keysize.\n");
        rsa_free(&key);
        free(ticket);
        exit(1);
    }
    
    //get the pseudo rng desc index
    int prng_idx = find_prng(PRNG);
    if (prng_idx < 0) {
        printf("Error getting prng index\n");
        rsa_free(&key);
        free(ticket);
        exit(1);
    }

    //get the hash desc index
    int hash_idx = find_hash(HASH);
    if (hash_idx < 0) {
        printf("Error getting hash index\n");
        rsa_free(&key);
        free(ticket);
        exit(1);
    }

    //allocate space for the padded and encrypted ticket
    uint8_t* paddingoutbuf = (uint8_t*)malloc(BUFFER_SIZE);
    memset(paddingoutbuf, 0, BUFFER_SIZE);
    uint64_t paddingoutlen = BUFFER_SIZE;

    uint8_t* encryptoutbuf = (uint8_t*)malloc(BUFFER_SIZE);
    memset(encryptoutbuf, 0, BUFFER_SIZE);
    uint64_t encryptoutlen = BUFFER_SIZE;

    if (!paddingoutbuf) {
        printf("Error malloc padding\n");
        rsa_free(&key);
        free(ticket);
        exit(1);
    }
    if (!encryptoutbuf) {
        printf("Error malloc enc\n");
        free(paddingoutbuf);
        free(ticket);
        rsa_free(&key);
        exit(1);
    }


    int err;
    //pad the ticket    
    if ((err = pkcs_1_oaep_encode(ticket, strlen(ticket), NULL, 0, keysizebytes * 8, NULL, prng_idx, hash_idx, paddingoutbuf, &paddingoutlen)) != CRYPT_OK) {
        printf("Error preforming padding: %s\n", error_to_string(err));
        free(paddingoutbuf);
        free(encryptoutbuf);
        free(ticket);
        rsa_free(&key);
        exit(1);
    }

    //encrypt the padded ticket
    if ((err = rsa_exptmod(paddingoutbuf, paddingoutlen, encryptoutbuf, &encryptoutlen, PK_PUBLIC, &key)) != CRYPT_OK) {
        printf("Error preforming encryption: %s\n", error_to_string(err));
        free(paddingoutbuf);
        free(encryptoutbuf);
        free(ticket);
        rsa_free(&key);
        exit(1);
    }

    //base64 encode the encrypted ticket
    uint64_t b64size = (uint64_t)ceil((double)encryptoutlen / 3) * 4 + 1;
    char* base64_out = malloc(b64size);
    if ((err = base64_encode(encryptoutbuf, encryptoutlen, base64_out, &b64size)) != CRYPT_OK){
        printf("Base64 error: %s\n", error_to_string(err));
    }
    printf("Please submit this ticket to the server: %s\n", base64_out);
    
    //cleanup
    free(ticket);
    free(encryptoutbuf);
    free(paddingoutbuf);
    rsa_free(&key);
    return 0;
}

uint8_t hexchar_to_value(char c) {
    if (c <= '9' && c >= '0') {
        return c - '0';
    }

    if (c <= 'F' && c >= 'A') {
        return c - 'A' + 10;
    }

    if (c <= 'f' && c >= 'a') {
        return c - 'a' + 10;
    }
}

uint8_t* hexstring_to_bytes(char* hexstring, uint64_t char_count) {
    uint8_t* buf = malloc(char_count / 2);
    if (!buf) {
        printf("Unable to allocate for hex to bytes\n");
        exit(1);
    }

    for (int i, j = 0; i < char_count; i+=2, ++j) {
        buf[j] = hexchar_to_value(hexstring[i]) * 16 + hexchar_to_value(hexstring[i+1]);
    }

    return buf;
}

char* build_ticket() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);


    int nssize = snprintf(NULL, 0, "%ld", ts.tv_nsec) + 1;
    int ssize = snprintf(NULL, 0, "%ld", ts.tv_sec) + 1;
    int usernamestrsize = strlen(USERNAME);

    int size = nssize + ssize + usernamestrsize + 2;

    char* ticket = malloc(size);
    if (!ticket) {
        printf("Unable to allocation memory for ticket.\n");
        exit(1);
    }

    memset(ticket, 0, size);
    memcpy(ticket, USERNAME, usernamestrsize);
    ticket[usernamestrsize] = ':';
    snprintf(&ticket[usernamestrsize+1], ssize, "%ld", ts.tv_sec);
    snprintf(&ticket[usernamestrsize+ssize], nssize, "%ld", ts.tv_nsec);

    return ticket;
}

void get_key(rsa_key* key) {
    int err;
    char* k = hexstring_to_bytes(KEY, KEYSIZE);
    err = rsa_import(k, KEYSIZE / 2, key);
    free(k);

    if (err != CRYPT_OK) {
        printf("Import key error: %s\n", error_to_string(err));
        rsa_free(key);
        exit(1);
    }

}

void setup_libtom() {
    ltc_mp = ltm_desc;
    
    int err;
    if ((err = register_all_ciphers()) != CRYPT_OK){
        printf("Error registering ciphers: %s\n", error_to_string(err));
    }
    if ((err = register_all_hashes()) != CRYPT_OK){
        printf("Error registering hashes: %s\n", error_to_string(err));
    }
    if ((err = register_all_prngs()) != CRYPT_OK){
        printf("Rrror registering prngs: %s\n", error_to_string(err));
    }
}