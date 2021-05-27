//
//  bech32.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-24.
//

#ifndef abstract_address_h
#define abstract_address_h

#include <stdio.h>
#include <stdbool.h>

// arbitrarily chosen
#define MAX_BECH32_DATA_PART_BYTE_COUNT 65

bool abstract_address_from_network_and_bytes(
    char *hrp,
    size_t hrplen,
                                    
    const uint8_t *in,
    size_t in_len,
                         
    bool should_pad,
                         
    char *out,
    size_t out_len
);

#endif /* abstract_address_h */
