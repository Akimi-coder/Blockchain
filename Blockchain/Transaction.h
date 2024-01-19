#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <iostream>
#include <cstdint> 
#include <openssl/sha.h>
#include <string>

class Transaction
{
private:
	uint64_t value;
	std::unique_ptr<std::string> from;
	std::unique_ptr<std::string> to;
	int nonce;
	uint64_t gas_limit;
	uint64_t max_fee_per_gas;
	unsigned char* hash;

public:
	Transaction(uint64_t val, std::unique_ptr<std::string> src, std::unique_ptr<std::string> dest,
		int n, uint64_t gas, uint64_t fee)
		: value(val), from(std::move(src)), to(std::move(dest)), nonce(n), gas_limit(gas),
		max_fee_per_gas(fee){
		hash = new unsigned char[SHA256_DIGEST_LENGTH];
	}

	Transaction(const Transaction& other)
		: value(other.value), from(std::make_unique<std::string>(*other.from)),
		to(std::make_unique<std::string>(*other.to)), nonce(other.nonce),
		gas_limit(other.gas_limit), max_fee_per_gas(other.max_fee_per_gas) {}

	// Getters
	int64_t get_value() const { return value; }
	std::string& get_from() const { return *from; }
	std::string& get_to() const { return *to; }
	int get_nonce() const { return nonce; }
	int64_t get_gas_limit() const { return gas_limit; }
	int64_t get_max_fee_per_gas() const { return max_fee_per_gas; }
	unsigned char* get_hash() const { return hash; }

public:
	void calculate_hash() const;
};
#endif // TRANSACTION_H