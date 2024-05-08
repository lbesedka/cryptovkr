#pragma once

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "../lib_ui/ui/text/text_entity.h"

namespace DF {
	enum States {
		WaitingForInit,
		WaitingForGPA,
		WaitingForB,
		KeyValid
	};

	enum Roles {
		Alice,
		Bob,
		Uninitialised
	};
}

typedef unsigned char BYTE;
extern unsigned char key[32];
extern unsigned char init_vector[16];
extern DF::States current_state;
extern DF::Roles current_role;


// base64

char* toBase64(unsigned char* text);
char* fromBase64(unsigned char* text);

// AES

BYTE* aesEncrypt(unsigned char* res);
BYTE* aesEncrypt(unsigned char* res, size_t size_of_plain_text);
void aesEncrypt_inplace(BYTE* res, size_t size_of_plain_text);

BYTE* aesDecrypt(unsigned char* res);
void aesDecrypt_inplace(BYTE* res, size_t size_of_plain_text);


bool isServiceMessage(std::string message);
int examineServiceMessage(std::string message);
std::tuple<BIGNUM*, BIGNUM*, BIGNUM*, BIGNUM*> generate_DH_parameters();
std::tuple<EVP_PKEY*, EVP_PKEY*, BIGNUM*, BIGNUM*> generate_DH_parameters2();
unsigned char* generateSharedKey(EVP_PKEY* publicKey, EVP_PKEY* privateKey, BIGNUM* prime, BIGNUM* generator);