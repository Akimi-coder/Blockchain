#pragma once
#include "Transaction.h"
#include <openssl/pem.h>
#include <string>
#include <secp256k1.h>

# define ADDRESS_SIZE    20

class Wallet
{
public:
	std::unique_ptr<std::string> secret_phrase;
	std::unique_ptr<unsigned char[]> private_key;
	secp256k1_pubkey public_key;
	std::unique_ptr<std::string> address;
	secp256k1_context* ctx;


public:
	Wallet(std::unique_ptr<std::string> phrase) : secret_phrase(std::move(phrase)) {
		private_key = std::make_unique<unsigned char[]>(SHA256_DIGEST_LENGTH);
		ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	}
	void generateKeyPair();
	unsigned char* sign(unsigned char *msg_hash);

};

