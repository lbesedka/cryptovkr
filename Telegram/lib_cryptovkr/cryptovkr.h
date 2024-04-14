#pragma once

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "../lib_ui/ui/text/text_entity.h"

typedef unsigned char BYTE;

// base64

char* toBase64(unsigned char* text);
char* fromBase64(unsigned char* text);

// AES

BYTE* aesEncrypt(unsigned char* res);
BYTE* aesDecrypt(unsigned char* res);

// ECDH

EVP_PKEY* keyGeneration();

TextWithTags encryptText(TextWithTags test);