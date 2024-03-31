#pragma once

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

typedef unsigned char BYTE;

// base64

char* toBase64(unsigned char* text);
char* fromBase64(unsigned char* text);

//
// AES

BYTE* aesEncrypt(unsigned char* res);
BYTE* aesDecrypt(unsigned char* res);

//