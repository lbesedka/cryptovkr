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

std::map<uint64_t, Network_n::SessionManager*> global_session_managers;

namespace DH_n {

	KeyGenerator::KeyGenerator() {
		prime = nullptr;
		generator = nullptr;
		public_key = nullptr;
		private_key = nullptr;
		external_public_key = nullptr;
		key_pair = nullptr;
	}

	KeyGenerator::KeyGenerator(BIGNUM* initial_prime, BIGNUM* initial_generator) {
		prime = initial_prime;
		generator = initial_generator;
		public_key = nullptr;
		private_key = nullptr;
		external_public_key = nullptr;
		key_pair = nullptr;
	}

	int KeyGenerator::set_prime(BIGNUM* new_prime) {
		if (new_prime) {
			prime = new_prime;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::set_generator(BIGNUM* new_generator) {
		if (new_generator) {
			generator = new_generator;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::set_private_key(EVP_PKEY* new_private_key) {
		if (new_private_key) {
			private_key = new_private_key;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::set_public_key(EVP_PKEY* new_public_key) {
		if (new_public_key) {
			public_key = new_public_key;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::set_external_key(EVP_PKEY* new_external_key) {
		if (new_external_key) {
			external_public_key = new_external_key;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::set_key_pair(EVP_PKEY* new_key_pair) {
		if (new_key_pair) {
			key_pair = new_key_pair;
			return 1;
		}
		return 0;
	}

	int KeyGenerator::generate_DH_parameters() {
		BIGNUM* big_add = BN_new();
		BIGNUM* big_rem = BN_new();

		BIGNUM* pub_bucket = BN_new();


		BN_set_word(big_add, 24);
		BN_set_word(big_rem, 23);

		int priv_len = 2 * 112;
		OSSL_PARAM params[3];
		EVP_PKEY* pkey = NULL;

		prime = BN_new();
		generator = BN_new();
		BN_set_word(big_add, 24);
		BN_set_word(big_rem, 23);


		EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);
		if (!pctx) {
			return 0;
		}

		params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"ffdhe2048", 0);
		params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
		params[2] = OSSL_PARAM_construct_end();

		if (EVP_PKEY_keygen_init(pctx) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		if (EVP_PKEY_CTX_set_params(pctx, params) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		if (EVP_PKEY_generate(pctx, &pkey) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}

		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &prime) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &generator) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}

		OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
		if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, prime) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, generator) == 0) {
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}

		OSSL_PARAM* param = OSSL_PARAM_BLD_to_param(paramBuild);
		EVP_PKEY_CTX* domainParamKeyCtx = EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr);

		if (EVP_PKEY_fromdata_init(domainParamKeyCtx) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}
		EVP_PKEY* domainParamKey = nullptr;
		if (EVP_PKEY_fromdata(domainParamKeyCtx, &domainParamKey, EVP_PKEY_KEY_PARAMETERS, param) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			return 0;
		}

		EVP_PKEY_CTX* keyGenerationCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey, nullptr);

		if (EVP_PKEY_keygen_init(keyGenerationCtx) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(keyGenerationCtx);
			return 0;
		}
		//EVP_PKEY* keyPair = nullptr;
		if (EVP_PKEY_generate(keyGenerationCtx, &key_pair) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(keyGenerationCtx);
			return 0;
		}

		if (EVP_PKEY_keygen(keyGenerationCtx, &private_key) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(keyGenerationCtx);
			return 0;
		}
		if (EVP_PKEY_keygen(keyGenerationCtx, &public_key) == 0) {
			EVP_PKEY_CTX_free(domainParamKeyCtx);
			EVP_PKEY_CTX_free(pctx);
			EVP_PKEY_CTX_free(keyGenerationCtx);
			return 0;
		}

		/*set_private_key(private_key);
		set_public_key(public_key);*/

		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_CTX_free(domainParamKeyCtx);
		EVP_PKEY_CTX_free(keyGenerationCtx);

		return 1;
	}

	BYTE* KeyGenerator::generateSharedKey() {
		if (!prime || !generator || !private_key || !external_public_key)
			return nullptr;

		BIGNUM* alesha = BN_new();
		BIGNUM* popovich = BN_new();
		BIGNUM* tugarin_zmey = BN_new();

		if (!EVP_PKEY_get_bn_param(private_key, OSSL_PKEY_PARAM_PRIV_KEY, &alesha) ||
			!EVP_PKEY_get_bn_param(public_key, OSSL_PKEY_PARAM_PUB_KEY, &popovich))
			return nullptr;

		OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
		if (!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, prime)|| 
			!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, generator) ||
			!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PRIV_KEY, alesha) ||
			!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, popovich))
			return nullptr;

		OSSL_PARAM* param = OSSL_PARAM_BLD_to_param(paramBuild);
		EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(public_key, NULL);

		if (EVP_PKEY_derive_init_ex(kctx, param) == 0) {
			EVP_PKEY_CTX_free(kctx);
			return nullptr;
		}
		if (EVP_PKEY_derive_set_peer_ex(kctx, external_public_key, 0) == 0) {
			EVP_PKEY_CTX_free(kctx);
			return nullptr;
		}

		size_t shared_key_len;
		BYTE* shared_key = NULL;
		if (EVP_PKEY_derive(kctx, NULL, &shared_key_len) == 0) {
			EVP_PKEY_CTX_free(kctx);
			return nullptr;
		}
		shared_key = (BYTE*)OPENSSL_malloc(shared_key_len);
		if (EVP_PKEY_derive(kctx, shared_key, &shared_key_len) == 0) {
			EVP_PKEY_CTX_free(kctx);
			return nullptr;
		}

		EVP_PKEY_CTX_free(kctx);
		return shared_key;
	}

	DiffieHellmanManager::DiffieHellmanManager() {
		current_state = States::WaitingForInit;
		current_role = Roles::Uninitialised;
		key_generator = KeyGenerator();
		rsa_manager = RSA_n::RsaManager::RsaManager();

		if (!get_rsa_manager()->read_private_key("./self/key.pem")) {
			get_rsa_manager()->generate_keys();
			get_rsa_manager()->write_private_key("./self/key.pem");
			get_rsa_manager()->write_public_key("./self/key.pub");
		}
	}
	DiffieHellmanManager::DiffieHellmanManager(States initial_state, Roles initial_role) {
		current_state = initial_state;
		current_role = initial_role;
		key_generator = KeyGenerator();
		rsa_manager = RSA_n::RsaManager::RsaManager();
	}
	DiffieHellmanManager::DiffieHellmanManager(States initial_state, Roles initial_role, std::string path_to_private_key) {
		current_state = initial_state;
		current_role = initial_role;
		key_generator = KeyGenerator();
		rsa_manager = RSA_n::RsaManager::RsaManager();
		/*if (!get_rsa_manager()->read_private_key(path_to_private_key)) {
			get_rsa_manager()->generate_keys();
		}*/
	}

	std::string DiffieHellmanManager::construct_pga_message() {
		if (!get_key_generator()->get_prime() || !get_key_generator()->get_generator() || !get_key_generator()->get_public_key())
			return "";


		std::string service = "";
		if (this->current_role == DH_n::Roles::Alice)
			service = "SERVICE_|PGA NUM_|";
		else if (this->current_role == DH_n::Roles::Bob)
			service = "SERVICE_|B NUM___|";
		else
			return "";

		std::string p_part = bignum_to_base64_string(get_key_generator()->get_prime());
		p_part.erase(std::remove(p_part.begin(), p_part.end(), '\n'), p_part.end());

		p_part += "|";
		std::string g_part = bignum_to_base64_string(get_key_generator()->get_generator());
		g_part.erase(std::remove(g_part.begin(), g_part.end(), '\n'), g_part.end());

		g_part += "|";
		char* a_part = key_to_base64_string(get_key_generator()->get_public_key());
		if (a_part == NULL)
			return "";
		std::string key_part = a_part;
		key_part.erase(std::remove(key_part.begin(), key_part.end(), '\n'), key_part.end());

		std::string message = service + p_part + g_part + key_part;
		std::string sign = get_rsa_manager()->sign_message_base64(message);
		sign.erase(std::remove(sign.begin(), sign.end(), '\n'), sign.end());


		return message + "|" + sign;
	}
	int DiffieHellmanManager::parse_pga_message(std::string message, std::string path_to_key) {
		if (message.length() < 18)
			return 0;
		std::string service = message.substr(0, 8);
		if (service != "SERVICE_")
			return 0;
		message.erase(0, message.find("|") + 1);

		std::string pga_num_service = message.substr(0, 8);
		if (pga_num_service != "PGA NUM_" && pga_num_service != "B NUM___")
			return 0;
		pga_num_service.erase(std::remove(pga_num_service.begin(), pga_num_service.end(), '\n'), pga_num_service.end());
		message.erase(0, message.find("|") + 1);

		std::string p_num = message.substr(0, message.find("|"));
		message.erase(0, message.find("|") + 1);
		p_num.erase(std::remove(p_num.begin(), p_num.end(), '\n'), p_num.end());

		std::string g_num = message.substr(0, message.find("|"));
		message.erase(0, message.find("|") + 1);
		g_num.erase(std::remove(g_num.begin(), g_num.end(), '\n'), g_num.end());

		std::string key = message.substr(0, message.find("|"));
		message.erase(0, message.find("|") + 1);
		key.erase(std::remove(key.begin(), key.end(), '\n'), key.end());

		std::string sign = message.substr(0);
		std::string message_copy = "SERVICE_|" + pga_num_service + "|" + p_num + "|" + g_num + "|" + key;

		get_rsa_manager()->read_public_key(path_to_key);
		if (!get_rsa_manager()->check_sign_from_base64(sign, message_copy))
			return 0;

		int success = 0;
		if (this->current_role == Roles::Bob) {
			success = get_key_generator()->set_prime(base64_string_to_bignum((char*)p_num.c_str()));
			success = get_key_generator()->set_generator(base64_string_to_bignum((char*)g_num.c_str()));
			get_key_generator()->generate_DH_parameters();
		}
		success = get_key_generator()->set_external_key(base64_string_to_key((char*)key.c_str()));

		return success;
	}

	char* DiffieHellmanManager::key_to_base64_string(EVP_PKEY* key) {
		BIO* bio = NULL;
		char* pem = NULL;

		if (NULL == key) {
			return NULL;
		}

		bio = BIO_new(BIO_s_mem());
		if (NULL == bio) {
			return NULL;
		}

		if (0 == PEM_write_bio_PUBKEY(bio, key)) {
			BIO_free(bio);
			return NULL;
		}

		BUF_MEM* bptr;
		BIO_get_mem_ptr(bio, &bptr);
		int length = bptr->length;

		pem = new char[length];

		BIO_read(bio, pem, length);
		BIO_free(bio);

		char* result = toBase64((unsigned char *)pem, length);
		//delete[] pem;

		return result;
	}
	EVP_PKEY* DiffieHellmanManager::base64_string_to_key(char* string) {
		char* new_string = fromBase64((unsigned char*)string);

		EVP_PKEY* key = NULL;
		BIO* bio = NULL;

		if (NULL == new_string) {
			return NULL;
		}

		bio = BIO_new_mem_buf(new_string, strlen(new_string));
		if (NULL == bio) {
			return NULL;
		}

		key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		BIO_free(bio);
		return key;
	}

	char* DiffieHellmanManager::bignum_to_base64_string(BIGNUM* bignum) {
		char* number_str = BN_bn2hex(bignum);
		/* sign */
		char* result = toBase64((BYTE*)number_str);
		return result;
	}
	BIGNUM* DiffieHellmanManager::base64_string_to_bignum(char* string) {
		char* new_string = fromBase64((BYTE*)string);
		/* check signature */
		BIGNUM* p = BN_new();
		BN_hex2bn(&p, new_string);
		return p;
	}
}

namespace AES_n {
	AesManager::AesManager() {
		init_vector = nullptr;
		key = nullptr;
		current_id = -1;
	}

	AesManager::AesManager(BYTE* init_vector, BYTE* key) {
		(init_vector) ? this->init_vector = init_vector : this->init_vector = nullptr;
		(key) ? this->key = key : this->key = nullptr;
		current_id = -1;
	}
	
	AesManager::~AesManager() {
		delete[] init_vector;
		delete[] key;
	}

	int AesManager::set_vector(BYTE* new_vector) {
		if (!new_vector)
			return 0;

		init_vector = new_vector;
		return 1;
	}

	int AesManager::set_key(BYTE* key) {
		if (!key)
			return 0;

		this->key = key;
		return 1;
	}

	BYTE* AesManager::aes_encrypt(BYTE* to_encrypt) {
		if (!key || !init_vector)
			return nullptr;

		EVP_CIPHER_CTX* ctx;
		ctx = EVP_CIPHER_CTX_new();
		int plain_text_len = strlen((char*)to_encrypt);
		int cipher_text_block_size = plain_text_len % AES_BLOCK_SIZE == 0 ? plain_text_len : (plain_text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

		BYTE* cipher_text = new BYTE[cipher_text_block_size];

		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, init_vector) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return nullptr;
		}

		int f_length, s_length;
		if (EVP_EncryptUpdate(ctx, cipher_text, &f_length, to_encrypt, plain_text_len) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return nullptr;
		}

		if (f_length == strlen((char*)cipher_text))
		{
			BYTE* tmp_ptr = nullptr;
			cipher_text = (BYTE*)realloc(cipher_text, cipher_text_block_size + AES_BLOCK_SIZE);
			tmp_ptr = cipher_text + cipher_text_block_size;
			memset(tmp_ptr, 0, AES_BLOCK_SIZE);
		}
		if (EVP_EncryptFinal_ex(ctx, cipher_text + f_length, &s_length) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return nullptr;
		}

		if (uint64_t(f_length + s_length) < strlen((char*)cipher_text)) {
			cipher_text = (BYTE*)realloc(cipher_text, f_length + s_length);
			cipher_text[f_length + s_length] = '\0';
		}
		EVP_CIPHER_CTX_free(ctx);

		return cipher_text;
	}

	void AesManager::aes_encrypt_inplace(BYTE* to_encrypt, size_t size_of_plain_text) {
		if (!key || !init_vector)
			return;

		EVP_CIPHER_CTX* ctx;
		ctx = EVP_CIPHER_CTX_new();
		int plain_text_len = size_of_plain_text;
		int cipher_text_block_size = plain_text_len % AES_BLOCK_SIZE == 0 ? plain_text_len : (plain_text_len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

		BYTE* cipher_text = new BYTE[cipher_text_block_size];

		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, init_vector) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}

		int f_length, s_length;
		if (EVP_EncryptUpdate(ctx, cipher_text, &f_length, (BYTE*)to_encrypt, plain_text_len) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}

		if (f_length == strlen((char*)cipher_text))
		{
			BYTE* tmp_ptr = nullptr;
			cipher_text = (BYTE*)realloc(cipher_text, cipher_text_block_size + AES_BLOCK_SIZE);
			tmp_ptr = cipher_text + cipher_text_block_size;
			memset(tmp_ptr, 0, AES_BLOCK_SIZE);
		}
		if (EVP_EncryptFinal_ex(ctx, cipher_text + f_length, &s_length) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}

		if (uint64_t(f_length + s_length) < strlen((char*)cipher_text)) {
			cipher_text = (BYTE*)realloc(cipher_text, f_length + s_length);
			cipher_text[f_length + s_length] = '\0';
		}
		EVP_CIPHER_CTX_free(ctx);

		memcpy(to_encrypt, cipher_text, f_length + s_length);
	}

	BYTE* AesManager::aes_decrypt(BYTE* to_decrypt) {
		if (!key || !init_vector)
			return nullptr;

		volatile int plain_text_len = strlen((char*)to_decrypt);
		BYTE* plain_text = new BYTE[plain_text_len];
		EVP_CIPHER_CTX* ctx;
		ctx = EVP_CIPHER_CTX_new();
		
		if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, init_vector) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return nullptr;
		}
		int f_length, s_length;
		if (EVP_DecryptUpdate(ctx, plain_text, &f_length, to_decrypt, plain_text_len) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return nullptr;
		}
		EVP_DecryptFinal_ex(ctx, plain_text + f_length, &s_length);
		plain_text = (BYTE*)realloc(plain_text, f_length + s_length);
		plain_text[f_length + s_length] = '\0';

		EVP_CIPHER_CTX_free(ctx);

		return plain_text;
	}

	void AesManager::aes_decrypt_inplace(BYTE* to_decrypt, size_t size_of_plain_text) {
		if (!key || !init_vector)
			return;

		BYTE* plain_text = new BYTE[size_of_plain_text];
		EVP_CIPHER_CTX* ctx;
		ctx = EVP_CIPHER_CTX_new();

		if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, init_vector) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
		int f_length, s_length;
		if (EVP_DecryptUpdate(ctx, plain_text, &f_length, to_decrypt, size_of_plain_text) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
		if (EVP_DecryptFinal_ex(ctx, plain_text + f_length, &s_length) == 0) {
			EVP_CIPHER_CTX_free(ctx);
			return;
		}
		plain_text = (BYTE*)realloc(plain_text, f_length + s_length);
		plain_text[f_length + s_length] = '\0';

		EVP_CIPHER_CTX_free(ctx);
		memcpy(to_decrypt, plain_text, f_length + s_length);
	}
}

namespace RSA_n {
	RsaManager::RsaManager() {	
		this->key = nullptr;
		if (!std::filesystem::exists("./self"))
			std::filesystem::create_directory("./self");
	}

	int RsaManager::write_private_key(std::string path) {
		if (!this->key)
			return 0;
		int success = 0;
		FILE* pkey = fopen(path.c_str(), "wb");
		if (!PEM_write_RSAPrivateKey(pkey, this->key, NULL, NULL, 0, NULL, NULL))
			success = 0;
		else
			success = 1;

		fclose(pkey);
		return success;
	}

	int RsaManager::write_public_key(std::string path) {
		if (!this->key)
			return 0;

		int success = 0;
		FILE* pubkey = fopen(path.c_str(), "wb");
		if (!PEM_write_RSAPublicKey(pubkey, this->key))
			success = 0;
		else
			success = 1;

		fclose(pubkey);
		return success;
	}

	int RsaManager::read_private_key(std::string path) {
		this->key = RSA_new();
		FILE* pkey = fopen(path.c_str(), "rb");
		if (pkey == nullptr)
			return 0;
		PEM_read_RSAPrivateKey(
			pkey,
			&this->key,
			NULL,
			NULL);

		fclose(pkey);
		return 1;
	}
	int RsaManager::read_public_key(std::string path) {
		this->key = RSA_new();
		FILE* pubkey = fopen(path.c_str(), "rb");
		if (pubkey == nullptr)
			return 0;
		PEM_read_RSAPublicKey(
			pubkey,
			&this->key,
			NULL,
			NULL);

		fclose(pubkey);
		return 1;
	}

	int RsaManager::generate_keys() {
		this->key = RSA_new();
		BIGNUM* bignum = NULL;
		bignum = BN_new();
		BN_set_word(bignum, RSA_F4);
		return RSA_generate_key_ex(this->key, 2048, bignum, NULL);
	}

	char* RsaManager::sign_message_base64(std::string message) {
		if (!this->key)
			return nullptr;
		BYTE* message_hash = SHA_n::ShaManager::get_sha_hash((char *)message.c_str(), message.size());

		const int size = RSA_size(this->key);
		BYTE* sign = new BYTE[size];
		unsigned int outlen = 0;
		RSA_sign(NID_sha256, message_hash, SHA256_DIGEST_LENGTH, sign, &outlen, this->key);

		char* base64_sign = toBase64(sign, size);

		return base64_sign;
	}

	volatile bool RsaManager::check_sign_from_base64(std::string sign, std::string message) {
		if (!this->key)
			return false;

		BYTE* message_hash = SHA_n::ShaManager::get_sha_hash((char*)message.c_str(), message.size());
		const int size = RSA_size(this->key);
		char* sign_bytes = fromBase64((BYTE*)sign.c_str());


		if (RSA_verify(NID_sha256, message_hash, SHA256_DIGEST_LENGTH, (BYTE *)sign_bytes, size, this->key) == 0)
			return false;
		else
			return true;
	}

}

namespace SHA_n {
	BYTE* ShaManager::get_sha_hash(char* to_hash, int size_to_hash) {
		BYTE* hash = new BYTE[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, to_hash, size_to_hash);
		SHA256_Final(hash, &sha256);

		return hash;
	}
}

namespace Network_n {
	SessionManager::SessionManager() {
		dhm_id = 0;
		session_start_time = std::time(nullptr);
		session_traffic_in_bytes = 0;
		aes_manager = AES_n::AesManager();
		dh_manager = DH_n::DiffieHellmanManager();
		crypto_needed = 1;
	}
	SessionManager::SessionManager(uint64_t dhm_id) {
		this->dhm_id = dhm_id;
		session_start_time = std::time(nullptr);
		session_traffic_in_bytes = 0;
		aes_manager = AES_n::AesManager();
		dh_manager = DH_n::DiffieHellmanManager();
		crypto_needed = 1;

		if (!std::filesystem::exists("./" + std::to_string(this->dhm_id)))
			std::filesystem::create_directory("./" + std::to_string(this->dhm_id));
	}

	bool SessionManager::is_service_message(std::string message) {
		std::string header = message.substr(0, 8);
		if (header == "SERVICE_")
			return 1;
		else
			return 0;
	}
	int SessionManager::handle_service_message(std::string message) {
		if (!is_service_message(message))
			return 0;
		std::string payload = message.substr(9, 8);
		if (payload.find("DH INIT_") != std::string::npos) {
			if (get_dh_manager()->get_state() != DH_n::States::WaitingForInit)
				return 0;
			else {
				get_dh_manager()->set_state(DH_n::States::SendingAcc);
				get_dh_manager()->set_role(DH_n::Roles::Bob);
				return 1;
			}
		}
		else if (payload.find("DH ACC__") != std::string::npos) {
			if (get_dh_manager()->get_state() != DH_n::States::WaitingForAcc || get_dh_manager()->get_role() == DH_n::Roles::Bob)
				return 0;
			else {
				get_dh_manager()->get_key_generator()->generate_DH_parameters();
				get_dh_manager()->set_state(DH_n::States::SendingGPA);
				return 1;
			}
		}
		else if (payload.find("PGA NUM_") != std::string::npos ) {
			if (get_dh_manager()->get_state() != DH_n::States::WaitingForGPA || get_dh_manager()->get_role() == DH_n::Roles::Alice)
				return 0;
			else {

				get_dh_manager()->parse_pga_message(message, "./" + std::to_string(this->dhm_id) + "/" + "key.pub");
				get_aes_manager()->set_key(get_dh_manager()->get_key_generator()->generateSharedKey());
				get_aes_manager()->set_vector(init_vector);
				get_dh_manager()->set_state(DH_n::States::SendingB);
				return 1;
			}

		}
		else if (payload.find("B NUM___") != std::string::npos) {
			if (get_dh_manager()->get_state() != DH_n::States::WaitingForB || get_dh_manager()->get_role() == DH_n::Roles::Bob)
				return 0;
			else {
				//get_dh_manager()->get_rsa_manager()->read_public_key("./" + std::to_string(this->dhm_id) + "/key.pub");

				get_dh_manager()->parse_pga_message(message, "./" + std::to_string(this->dhm_id) + "/" + "key.pub");
				get_aes_manager()->set_key(get_dh_manager()->get_key_generator()->generateSharedKey());
				get_aes_manager()->set_vector(init_vector);
				this->reset_counters();
				get_dh_manager()->set_state(DH_n::States::KeyValid);
				get_dh_manager()->set_role(DH_n::Roles::Uninitialised);
				return 1;
			}
		}
		else {
			return 0;
		}
	}

	void SessionManager::reset_counters() {
		session_start_time = std::time(nullptr);
		session_traffic_in_bytes = 0;
	}

	bool SessionManager::is_key_change_needed(std::time_t time_in_minutes, std::size_t size_in_megabytes){
		if (this->get_elapsed_time_in_minutes() > time_in_minutes || this->get_session_traffic_in_megabytes() > size_in_megabytes)
			return true;
		else
			return false;
	}

	int SessionManager::serialize_aes_key(){
		if (!get_aes_manager()->get_key() || !get_aes_manager()->get_vector())
			return 0;
		json aes_key_json;

		aes_key_json["id"] = get_aes_manager()->current_id;
		aes_key_json["key"] = toBase64(get_aes_manager()->get_key());
		aes_key_json["init_vector"] = toBase64(get_aes_manager()->get_vector());
		aes_key_json["external_key"] = get_dh_manager()->key_to_base64_string(get_dh_manager()->get_key_generator()->get_external_key());
		aes_key_json["pub_key"] = get_dh_manager()->key_to_base64_string(get_dh_manager()->get_key_generator()->get_public_key());
		aes_key_json["p"] = get_dh_manager()->bignum_to_base64_string(get_dh_manager()->get_key_generator()->get_prime());
		aes_key_json["g"] = get_dh_manager()->bignum_to_base64_string(get_dh_manager()->get_key_generator()->get_generator());

		std::ofstream o("./" + std::to_string(dhm_id) + "/" + std::to_string(get_aes_manager()->current_id) + ".json");
		o << std::setw(4) << aes_key_json << std::endl;

		return 1;
	}

	int SessionManager::deserialize_aes_key(std::string path_to_config) {
		if (!get_aes_manager()->get_key() || !get_aes_manager()->get_vector())
			return 0;
		json aes_key_json;

		std::ifstream f(path_to_config);
		aes_key_json = json::parse(f);

		std::string tmp_key = aes_key_json["key"];
		std::string tmp_vector = aes_key_json["init_vector"];
		get_aes_manager()->set_key((BYTE *)fromBase64((BYTE *)tmp_key.c_str()));
		get_aes_manager()->set_vector((BYTE*)fromBase64((BYTE*)tmp_vector.c_str()));
		get_aes_manager()->current_id = aes_key_json["id"];
		
		return 1;
	}

	int SessionManager::save_rsa_pkey_to_file(bool self) {
		if (!get_dh_manager()->get_rsa_manager()->get_key())
			return 0;

		std::string path_to_file;
		if (self)
			path_to_file = "./self/key.pem";
		else
			path_to_file = "./" + std::to_string(dhm_id) + "/" + "key.pem";

		get_dh_manager()->get_rsa_manager()->write_private_key(path_to_file);
		return 1;
	}
	int SessionManager::save_rsa_pubkey_to_file(bool self) {
		if (!get_dh_manager()->get_rsa_manager()->get_key())
			return 0;

		std::string path_to_file;
		if (self)
			path_to_file = "./self/key.pub";
		else
			path_to_file = "./" + std::to_string(dhm_id) + "/" + "key.pub";

		get_dh_manager()->get_rsa_manager()->write_public_key(path_to_file);
		return 1;
	}
}

namespace Service_n {
	void Config::deserialize_config(std::string path_to_config) {
		json config;

		std::ifstream f(path_to_config);
		config = json::parse(f);

		this->max_session_time = config["max_session_time"];
		this->max_session_traffic_in_bytes = config["max_session_traffic_in_bytes"];
		this->time_until_screenlock = config["time_until_screenlock"];
	}

	void Config::serialize_config(std::string path_to_config) {
		json config;

		config["max_session_time"] = this->max_session_time;
		config["max_session_traffic_in_bytes"] = this->max_session_traffic_in_bytes;
		config["time_until_screenlock"] = this->time_until_screenlock;

		std::ofstream o(path_to_config);
		o << std::setw(4) << config << std::endl;
	}
}

std::mutex global_session_managers_mutex;


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

char* toBase64(unsigned char* text, int initial_len) {
	/*int len_text = strlen((const char*)text);
	//int len_encoded = 4 * ((len_text + 2) / 3) + 1;
	//char* encoded_data = new char[len_encoded];
	//EVP_EncodeBlock((unsigned char*)encoded_data, text, len_text);
	////encoded_data[len_encoded - 1] = '\0';
	//return encoded_data;*/

	int success_flag = 0;
	EVP_ENCODE_CTX* ctx;
	ctx = EVP_ENCODE_CTX_new();
	int len_text = initial_len;
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

char* fromBase64(unsigned char* text, int initial_size) {
	EVP_ENCODE_CTX* ctx;
	ctx = EVP_ENCODE_CTX_new();
	int len_text = initial_size;
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
