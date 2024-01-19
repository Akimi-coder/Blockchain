#include "Transaction.h"

void Transaction::calculate_hash() const {

	std::string transaction = std::to_string(value) + *from + *to +
		std::to_string(nonce) + std::to_string(gas_limit) + std::to_string(max_fee_per_gas);
	;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, transaction.c_str(), transaction.length());
	SHA256_Final(hash, &sha256);
}