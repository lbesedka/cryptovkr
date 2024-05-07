// lib_cryptovkr.cpp : Определяет функции для статической библиотеки.
//
#include "pch.h"
#include "cryptovkr.h"

#define AES_BLOCK_SIZE 16
#define BASE64_TO_ENCODE_BLOCK_SIZE 48
#define BASE64_ENCODED_BLOCK_SIZE 65


unsigned char key[32] = {
		0x61,0x73,0x61,0x73,0x64,0x61,0x73,0x63,0x6c,0x61,0x6e,0x6f,0x76,0x69,0x63,0x68,\
		0x61,0x73,0x61,0x73,0x64,0x61,0x73,0x63,0x6c,0x61,0x6e,0x6f,0x76,0x69,0x63,0x68
};

unsigned char init_vector[16] = {
		0x61,0x73,0x61,0x73,0x64,0x61,0x73,0x63,0x6c,0x61,0x6e,0x6f,0x76,0x69,0x63,0x68
};

DF::Roles current_role = DF::Roles::Uninitialised;

DF::States current_state = DF::States::WaitingForInit;

int calculateBufferSize(int len_of_text) {
	int whole_blocks = std::floor((len_of_text / BASE64_TO_ENCODE_BLOCK_SIZE));
	int partial_block_size = len_of_text % BASE64_TO_ENCODE_BLOCK_SIZE;
	if (partial_block_size > 0)
		whole_blocks += 1;
	return (whole_blocks * BASE64_ENCODED_BLOCK_SIZE) + 1;
}


char* toBase64(unsigned char* text) {
	/*int len_text = strlen((const char*)text);
	//int len_encoded = 4 * ((len_text + 2) / 3) + 1;
	//char* encoded_data = new char[len_encoded];
	//EVP_EncodeBlock((unsigned char*)encoded_data, text, len_text);
	////encoded_data[len_encoded - 1] = '\0';
	//return encoded_data;*/

	int success_flag = 0;
	EVP_ENCODE_CTX* ctx;
	ctx = EVP_ENCODE_CTX_new();
	int len_text = strlen((const char*)text);
	int len_encoded = calculateBufferSize(len_text);
	char* encoded_data = new char[len_encoded];
	EVP_EncodeInit(ctx);
	int dlen;
	success_flag = EVP_EncodeUpdate(ctx, (unsigned char*)encoded_data, &dlen, text, len_text);
	EVP_EncodeFinal(ctx, (unsigned char*)encoded_data + dlen, &dlen);
	EVP_ENCODE_CTX_free(ctx);

	if (dlen == 0 && !success_flag)
		return (char*)text;
	return encoded_data;

}

char* fromBase64(unsigned char* text) {
	/*int len_text = strlen((const char*)text);
	int len_decoded_data = (3 * len_text / 4) + 1;
	char* decoded_data = new char[len_decoded_data];
	int len_decoded = EVP_DecodeBlock((unsigned char*)decoded_data, text, len_text);
	if (len_decoded == -1)
		return (char*)text;
	if (len_decoded < len_decoded_data)
		decoded_data = (char*)realloc(decoded_data, len_decoded);
	decoded_data[len_decoded - 1] = '\0';
	return decoded_data; */
	EVP_ENCODE_CTX* ctx;
	ctx = EVP_ENCODE_CTX_new();
	int len_text = strlen((const char*)text);
	int len_decoded_data = (3 * len_text / 4) + 1;
	char* decoded_data = new char[len_decoded_data];
	EVP_DecodeInit(ctx);
	int final_len;
	int dlen;
	if (-1 == EVP_DecodeUpdate(ctx, (unsigned char*)decoded_data, &dlen, text, len_text))
		return (char*)text;
	final_len = dlen;
	EVP_DecodeFinal(ctx, (unsigned char*)decoded_data + final_len, &dlen);
	final_len += dlen;
	EVP_ENCODE_CTX_free(ctx);
	decoded_data[final_len] = '\0';
	return decoded_data;
}

BYTE* aesEncrypt(unsigned char* res) {
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	int plain_text_len = strlen((char*)res);
	int cipher_text_block_size = plain_text_len % AES_BLOCK_SIZE == 0 ? plain_text_len : (plain_text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

	BYTE* cipher_text = new BYTE[cipher_text_block_size];

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, init_vector);

	int f_length, s_length;
	EVP_EncryptUpdate(ctx, cipher_text, &f_length, res, plain_text_len);

	if (f_length == strlen((char*)cipher_text))
	{
		BYTE* tmp_ptr = nullptr;
		cipher_text = (BYTE*)realloc(cipher_text, cipher_text_block_size + AES_BLOCK_SIZE);
		tmp_ptr = cipher_text + cipher_text_block_size;
		memset(tmp_ptr, 0, AES_BLOCK_SIZE);
	}
	EVP_EncryptFinal_ex(ctx, cipher_text + f_length, &s_length);

	if (uint64_t(f_length + s_length) < strlen((char*)cipher_text)) {
		cipher_text = (BYTE*)realloc(cipher_text, f_length + s_length);
		cipher_text[f_length + s_length] = '\0';
	}
	EVP_CIPHER_CTX_free(ctx);

	return cipher_text;
}

BYTE* aesEncrypt(unsigned char* res, size_t size_of_plain_text) {
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	int plain_text_len = size_of_plain_text;
	int cipher_text_block_size = plain_text_len % AES_BLOCK_SIZE == 0 ? plain_text_len : (plain_text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

	BYTE* cipher_text = new BYTE[cipher_text_block_size];

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, init_vector);

	int f_length, s_length;
	EVP_EncryptUpdate(ctx, cipher_text, &f_length, res, plain_text_len);

	if (f_length == strlen((char*)cipher_text))
	{
		BYTE* tmp_ptr = nullptr;
		cipher_text = (BYTE*)realloc(cipher_text, cipher_text_block_size + AES_BLOCK_SIZE);
		tmp_ptr = cipher_text + cipher_text_block_size;
		memset(tmp_ptr, 0, AES_BLOCK_SIZE);
	}
	EVP_EncryptFinal_ex(ctx, cipher_text + f_length, &s_length);

	if (uint64_t(f_length + s_length) < strlen((char*)cipher_text)) {
		cipher_text = (BYTE*)realloc(cipher_text, f_length + s_length);
		cipher_text[f_length + s_length] = '\0';
	}
	EVP_CIPHER_CTX_free(ctx);

	return cipher_text;
}

BYTE* aesDecrypt(unsigned char* res) {
	int plain_text_len = strlen((char*)res);
	BYTE* plain_text = new BYTE[plain_text_len];
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, init_vector);
	int f_length, s_length;
	EVP_DecryptUpdate(ctx, plain_text, &f_length, res, plain_text_len);
	EVP_DecryptFinal_ex(ctx, plain_text + f_length, &s_length);
	plain_text = (BYTE*)realloc(plain_text, f_length + s_length);
	plain_text[f_length + s_length] = '\0';

	EVP_CIPHER_CTX_free(ctx);

	return plain_text;
}

void aesDecrypt_inplace(BYTE* res, size_t size_of_plain_text) {
	BYTE* plain_text = new BYTE[size_of_plain_text];
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, init_vector);
	int f_length, s_length;
	EVP_DecryptUpdate(ctx, plain_text, &f_length, res, size_of_plain_text);
	EVP_DecryptFinal_ex(ctx, plain_text + f_length, &s_length);
	plain_text = (BYTE*)realloc(plain_text, f_length + s_length);
	plain_text[f_length + s_length] = '\0';

	EVP_CIPHER_CTX_free(ctx);
	memcpy(res, plain_text, f_length + s_length);
}

void aesEncrypt_inplace(BYTE* res, size_t size_of_plain_text) {
	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	int plain_text_len = size_of_plain_text;
	int cipher_text_block_size = plain_text_len % AES_BLOCK_SIZE == 0 ? plain_text_len : (plain_text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

	BYTE* cipher_text = new BYTE[cipher_text_block_size];

	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, init_vector);

	int f_length, s_length;
	EVP_EncryptUpdate(ctx, cipher_text, &f_length, (BYTE*)res, plain_text_len);

	if (f_length == strlen((char*)cipher_text))
	{
		BYTE* tmp_ptr = nullptr;
		cipher_text = (BYTE*)realloc(cipher_text, cipher_text_block_size + AES_BLOCK_SIZE);
		tmp_ptr = cipher_text + cipher_text_block_size;
		memset(tmp_ptr, 0, AES_BLOCK_SIZE);
	}
	EVP_EncryptFinal_ex(ctx, cipher_text + f_length, &s_length);

	if (uint64_t(f_length + s_length) < strlen((char*)cipher_text)) {
		cipher_text = (BYTE*)realloc(cipher_text, f_length + s_length);
		cipher_text[f_length + s_length] = '\0';
	}
	EVP_CIPHER_CTX_free(ctx);

	memcpy(res, cipher_text, f_length + s_length);
	//delete[] cipher_text;
}

bool isServiceMessage(std::string message) {
	std::string header = message.substr(0, 8);
	if (header == "SERVICE_|")
		return 1;
	else
		return 0;
}

int examineServiceMessage(std::string message) {
	if (!isServiceMessage(message))
		return 0;
	std::string payload = message.substr(9, 8);
	if (payload.find("DH INIT_") != std::string::npos) {
		if (current_state != DF::States::WaitingForInit)
			return 0;
		else {
			/*send message DH ACC__*/
			current_state = DF::States::WaitingForGPA;
			current_role = DF::Roles::Bob;
			return 1;
		}
	}
	else if (payload.find("DH ACC__")) {
		if (current_state != DF::States::WaitingForInit || current_role == DF::Roles::Bob)
			return 0;
		else {
			current_state = DF::States::WaitingForB;
			/*generate_pga()*/
			/*send p*/
			/*send g*/
			/*send a*/
			return 1;
		}
	}
	else if (payload.find("PGA NUM_")) {
		if (current_state != DF::States::WaitingForGPA || current_role == DF::Roles::Alice)
			return 0;
		else {
			/*generate b*/
			/*send b*/
			/*get K*/
			return 1;
		}
		
	}
	else if (payload.find("B NUM___")) {
		if (current_state != DF::States::WaitingForB || current_role == DF::Roles::Bob)
			return 0;
		else {
			/*get K*/
			return 1;
		}
	}
	else if (payload.find("DF END__")) {
		if (current_state != DF::States::KeyValid)
			return 0;
		else {
			/*obnulyai counter*/
			return 1;
		}
	}
	else {
		return 0;
	}
}


std::tuple<BIGNUM*, BIGNUM*, BIGNUM*, BIGNUM*> generate_DH_parameters() {
	BIGNUM* big_add = BN_new();
	BIGNUM* big_rem = BN_new();

	BN_set_word(big_add, 24);
	BN_set_word(big_rem, 23);

	int priv_len = 2 * 112;
	OSSL_PARAM params[3];
	BIGNUM* prime;
	BIGNUM* generator;
	EVP_PKEY* pkey = NULL;

	prime = BN_new();
	generator = BN_new();
	BN_set_word(big_add, 24);
	BN_set_word(big_rem, 23);


	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

	params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"ffdhe2048", 0);
	/* "priv_len" is optional */
	params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
	params[2] = OSSL_PARAM_construct_end();

	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_params(pctx, params);
	EVP_PKEY_generate(pctx, &pkey);

	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &prime);
	EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &generator);

	OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();

	// Set the prime and generator.
	OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, prime);
	OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, generator);
	// Convert to OSSL_PARAM.
	OSSL_PARAM* param = OSSL_PARAM_BLD_to_param(paramBuild);

	// Create the context. The name is DHX not DH!!!
	EVP_PKEY_CTX* domainParamKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr);

	// Initialize the context.
	EVP_PKEY_fromdata_init(domainParamKeyCtx);
	// Create the domain parameter key.
	EVP_PKEY* domainParamKey = nullptr;
	EVP_PKEY_fromdata(domainParamKeyCtx, &domainParamKey, EVP_PKEY_KEY_PARAMETERS, param);

	EVP_PKEY_CTX* keyGenerationCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey, nullptr);

	EVP_PKEY_keygen_init(keyGenerationCtx);
	EVP_PKEY* keyPair = nullptr;
	EVP_PKEY_generate(keyGenerationCtx, &keyPair);
	
	BIGNUM* publicKey = nullptr;
	EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, &publicKey);

	BIGNUM* privateKey = nullptr;
	EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PRIV_KEY, &privateKey);


	std::tuple<BIGNUM*, BIGNUM*, BIGNUM*, BIGNUM*> tup = { publicKey, privateKey, prime, generator };
	return tup;
	
}


