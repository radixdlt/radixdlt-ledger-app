//
//  bech32.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-24.
//

#ifndef address_from_network_and_bytes_h
#define address_from_network_and_bytes_h

#include <stdio.h>
#include <stdbool.h>

#define MAX_INPUT_SIZE 64

bool address_from_network_and_bytes(
    bool is_mainnet, // else betanet
    const uint8_t *in,
    size_t in_len,
                         
    uint8_t pad,
                         
    char *out,
    size_t out_len);

#endif /* address_from_network_and_bytes_h */
