#pragma once

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <ctime>
#include <json.hpp>
#include <fstream>
#include <filesystem>
#include <mutex>

using json = nlohmann::json;
typedef unsigned char BYTE;

namespace RSA_n {
	class RsaManager {
	public:
		RsaManager();

		int generate_keys();

		RSA* get_key() { return key; }
		void set_key(RSA* new_key) { key = new_key; }

		int write_private_key(std::string path);
		int write_public_key(std::string path);

		int read_private_key(std::string path);
		int read_public_key(std::string path);

		char* sign_message_base64(std::string message);
		volatile bool check_sign_from_base64(std::string sign, std::string message);

	private:
		RSA* key;
	};
}

namespace SHA_n {
	class ShaManager {
	public:
		static BYTE* get_sha_hash(char* to_hash, int size_to_hash);
	};
}

namespace DH_n {
	enum States {
		WaitingForInit,
		WaitingForGPA,
		WaitingForB,
		WaitingForAcc,
		KeyValid,
		SendingAcc,
		SendingGPA,
		SendingB,
		SendingA
	};

	enum Roles {
		Alice,
		Bob,
		Uninitialised
	};

	class KeyGenerator {
	public:
		KeyGenerator();
		KeyGenerator(BIGNUM* initial_prime, BIGNUM* initial_generator);

		BIGNUM* get_prime() { return prime; }
		BIGNUM* get_generator() { return generator; }
		EVP_PKEY* get_private_key() { return private_key; }
		EVP_PKEY* get_public_key() { return public_key; }
		EVP_PKEY* get_external_key() { return external_public_key; }
		int set_prime(BIGNUM* new_prime);
		int set_generator(BIGNUM* new_generator);
		int set_private_key(EVP_PKEY* new_private_key);
		int set_public_key(EVP_PKEY* new_public_key);
		int set_external_key(EVP_PKEY* new_external_key);
		int set_key_pair(EVP_PKEY* new_key_pair);
		int generate_DH_parameters();
		BYTE* generateSharedKey();


	private:
		BIGNUM* prime;
		BIGNUM* generator;
		EVP_PKEY* private_key;
		EVP_PKEY* public_key;
		EVP_PKEY* external_public_key;
		EVP_PKEY* key_pair;
	};

	class DiffieHellmanManager {
	public:
		DiffieHellmanManager();
		DiffieHellmanManager(States initial_state, Roles initial_role);
		DiffieHellmanManager(States initial_state, Roles initial_role, std::string path_to_private_key);

		States get_state() { return current_state; }
		Roles get_role() { return current_role; }
		KeyGenerator* get_key_generator() { return &key_generator; }
		RSA_n::RsaManager* get_rsa_manager() { return &rsa_manager; }
		void set_state(States new_state) { current_state = new_state; }
		void set_role(Roles new_role) { current_role = new_role; }

		std::string construct_pga_message();
		int parse_pga_message(std::string message, std::string path_to_key);

		static char* key_to_base64_string(EVP_PKEY* key);
		static EVP_PKEY* base64_string_to_key(char* string);
		
		static char* bignum_to_base64_string(BIGNUM* bignum);
		static BIGNUM* base64_string_to_bignum(char* string);

		KeyGenerator key_generator;
		RSA_n::RsaManager rsa_manager;

	private:
		States current_state;
		Roles current_role;
	};
}

namespace AES_n {
	class AesManager {
	public:
		AesManager();
		AesManager(BYTE* init_vector, BYTE* key);
		~AesManager();

		BYTE* get_vector() { return init_vector; }
		BYTE* get_key() { return key; }
		int set_vector(BYTE* init_vector);
		int set_key(BYTE* key);

		BYTE* aes_encrypt(BYTE* to_encrypt);
		void aes_encrypt_inplace(BYTE* to_encrypt, size_t size_of_plain_text);
		BYTE* aes_decrypt(BYTE* to_decrypt);
		void aes_decrypt_inplace(BYTE* to_decrypt, size_t size_of_plain_text);

		int current_id;
	private:
		BYTE* init_vector;
		BYTE* key;
	};
}

namespace Network_n {
	class SessionManager {
	public:
		SessionManager();
		SessionManager(uint64_t dhm_id);

		uint64_t get_id() { return dhm_id; }
		DH_n::DiffieHellmanManager* get_dh_manager() { return &dh_manager; }
		AES_n::AesManager* get_aes_manager() { return &aes_manager; }
		int get_session_traffic_in_megabytes() { return session_traffic_in_bytes * 0.000001; };
		std::time_t get_elapsed_time() { return std::time(nullptr) - session_start_time; };
		std::time_t get_elapsed_time_in_minutes() { return (std::time(nullptr) - session_start_time) / 60; };

		void set_id(uint64_t new_id) { dhm_id = new_id; }
		void set_session_traffic(std::size_t traffic_in_bytes) { session_traffic_in_bytes = traffic_in_bytes; }
		void set_elapsed_time(std::time_t time) { session_start_time = time; }

		bool is_service_message(std::string message);
		int handle_service_message(std::string message);
		std::string handle_encrypted_message(std::string message);
		std::string construct_encrypted_message(std::string message);

		void reset_counters();
		bool is_key_change_needed(std::time_t time_in_minutes, std::size_t size_in_megabytes);

		int serialize_aes_key();
		int deserialize_aes_key(std::string path_to_config);
		int get_highest_aes_id();

		int save_rsa_pkey_to_file(bool self);
		int save_rsa_pubkey_to_file(bool self);

		
	private:
		uint64_t dhm_id;
		bool crypto_needed;
		std::time_t session_start_time;
		std::size_t session_traffic_in_bytes;
		DH_n::DiffieHellmanManager dh_manager;
		AES_n::AesManager aes_manager;
	};
}

namespace Service_n {
	class Config {
	public:
		std::time_t max_session_time;
		std::size_t max_session_traffic_in_bytes;
		std::time_t time_until_screenlock;
		void serialize_config(std::string path_to_config);
		void deserialize_config(std::string path_to_config);
	};
}

//extern unsigned char key[32];
extern unsigned char init_vector[16];

extern std::map<uint64_t, Network_n::SessionManager *> global_session_managers;
extern std::mutex global_session_managers_mutex;

// base64

char* toBase64(unsigned char* text);
char* toBase64(unsigned char* text, int initial_len);
char* fromBase64(unsigned char* text);
char* fromBase64(unsigned char* text, int initial_size);
