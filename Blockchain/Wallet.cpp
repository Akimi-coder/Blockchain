#include "Wallet.h"
#include <secp256k1_recovery.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>



static void print_hex(unsigned char* data, size_t size) {
	size_t i;
	printf("0x");
	for (i = 0; i < size; i++) {
		printf("%02x", data[i]);
	}
	printf("\n");
}



void Wallet::generateKeyPair() {

	unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, secret_phrase->c_str(), secret_phrase->length());
    SHA256_Final(hash, &sha256);
	std::memcpy(private_key.get(), hash, SHA256_DIGEST_LENGTH);
	secp256k1_ec_pubkey_create(ctx, &public_key, private_key.get());

    unsigned char serialized_public_key[65];
    size_t output_length = 65;
    secp256k1_ec_pubkey_serialize(ctx, serialized_public_key, &output_length, &public_key, SECP256K1_EC_UNCOMPRESSED);


    unsigned char address_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, serialized_public_key + 1, sizeof(serialized_public_key));
    SHA256_Final(address_hash, &sha256);
    std::stringstream ss;
    std::string ethereum_address;
    for (int i = SHA256_DIGEST_LENGTH - 20; i < SHA256_DIGEST_LENGTH; ++i) {        
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    address = std::make_unique<std::string>(ss.str());
}



unsigned char* Wallet::sign(unsigned char *msg_hash) {
	unsigned char* serialized_signature = new unsigned char[64];
	secp256k1_ecdsa_signature sig;
	secp256k1_ecdsa_sign(ctx, &sig, msg_hash, private_key.get(), NULL, NULL);
	secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
	return serialized_signature;
}