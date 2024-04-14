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

//Diffie-Hellman on eliptic curvies
EVP_PKEY* keyGeneration() {
	EVP_PKEY* key_pair = 0;
	EVP_PKEY_CTX* param_gen_ctx = nullptr; 	
	EVP_PKEY_CTX* key_gen_ctx = nullptr;		
	EVP_PKEY* params = nullptr;
	param_gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	EVP_PKEY_paramgen_init(param_gen_ctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_gen_ctx, NID_X9_62_prime256v1);
	EVP_PKEY_paramgen(param_gen_ctx, &params);
	key_gen_ctx = EVP_PKEY_CTX_new(params, nullptr);
	EVP_PKEY_keygen_init(key_gen_ctx);
	EVP_PKEY_keygen(key_gen_ctx, &key_pair);
	EVP_PKEY_CTX_free(param_gen_ctx);
	EVP_PKEY_CTX_free(key_gen_ctx);
	return key_pair;
}

//BYTE extractPubKey(EVP_PKEY* key_pair) {
//	EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(key_pair);
//	EC_POINT* ec_point = const_cast<EC_POINT*>(EC_KEY_get0_public_key(ec_key));
//
//	EVP_PKEY* public_key = EVP_PKEY_new();
//	EC_KEY* public_ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//
//	EC_KEY_set_public_key(public_ec_key, ec_point);
//	EVP_PKEY_set1_EC_KEY(public_key, public_ec_key);
//
//	EC_KEY* temp_ec_key = EVP_PKEY_get0_EC_KEY(public_key);
//	const EC_GROUP* group = EC_KEY_get0_group(temp_ec_key);
//	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
//
//	unsigned char* pub_key_buffer;
//	size_t length = EC_KEY_key2buf(temp_ec_key, form, &pub_key_buffer, NULL);
//	BYTE* data(pub_key_buffer, length);
//
//	OPENSSL_free(pub_key_buffer);
//	EVP_PKEY_free(public_key);
//	EC_KEY_free(ec_key);
//	EC_KEY_free(public_ec_key);
//	EC_POINT_free(ec_point);
//
//	return data;
//
//}
//

