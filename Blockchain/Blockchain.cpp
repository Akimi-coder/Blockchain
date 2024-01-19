/*************************************************************************
 * Written in 2020-2022 by Elichai Turkel                                *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <iomanip>
#include <string.h>
#include <iostream>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <openssl/sha.h>
#include "Wallet.h"
#include "Miner.h"

unsigned char* calculateSHA256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);

    // Convert the hash to a hexadecimal string
    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        char hex[3];
        sprintf_s(hex, "%02x", hash[i]);
        result += hex;
    }

    return hash;
}

static void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


int main(void) {

    
    std::unique_ptr<std::string> sec_phrase = std::make_unique<std::string>("word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12");

    Wallet* myWallet = new Wallet(std::move(sec_phrase));

    myWallet->generateKeyPair();
    
    uint64_t value = 100;
    auto to = std::make_unique<std::string>("RecipientAddress");
    int nonce = 1;
    uint64_t gas_limit = 1000;
    uint64_t max_fee_per_gas = 10;
    Transaction* tx = new Transaction(value, std::move(myWallet->address), std::move(to), nonce, gas_limit, max_fee_per_gas);
    unsigned char* sign = myWallet->sign(tx->get_hash());
    Miner* miner = new Miner();
    int res = miner->verify_transaction(sign, tx->get_hash());
    std::cout << res;

}
