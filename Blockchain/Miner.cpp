#include "Miner.h"


static void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int Miner::verify_transaction(unsigned char* signature, unsigned char* transaction_hash) {
    secp256k1_ecdsa_recoverable_signature recoverablesignature;
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverablesignature, signature, 0);
    secp256k1_pubkey pubkeyrecovery;
    int result = secp256k1_ecdsa_recover(ctx, &pubkeyrecovery, &recoverablesignature, transaction_hash);
    return result;
}
