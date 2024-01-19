#include "Transaction.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <iostream>


class Miner
{
private:
	secp256k1_context* ctx;


public:
	Miner() {
		ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	}
public:
	int verify_transaction(unsigned char* signature, unsigned char* transaction_hash);
};

