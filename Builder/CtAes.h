#pragma once

#ifndef CTAES_H
#define CTAES_H

#include <Windows.h>
#include <stdint.h> 

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;


void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv);
void AES256_CBC_encrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain);
void AES256_CBC_decrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char* encrypted);

#endif // CTAES_H