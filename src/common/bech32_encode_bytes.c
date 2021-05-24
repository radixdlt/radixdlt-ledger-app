/*******************************************************************************
*   (c) 2019 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include "bech32_encode_bytes.h"
#include "os.h"
#include "segwit_addr.h"

bool address_from_network_and_bytes(
    bool is_mainnet, // else betanet
    const uint8_t *in,
    size_t in_len,
                         
    uint8_t pad,
                         
    char *out,
    size_t out_len
) {
    explicit_bzero(out, out_len);

    if (in_len > MAX_INPUT_SIZE) {
        PRINTF("bech32 encoding failed, out of bounds.\n");
        return false;
    }

    size_t hrplen = 3;
    char hrp[hrplen];
    
    if (is_mainnet) {
        os_memmove(hrp, "rdx", hrplen);
    } else {
        // betanet
        os_memmove(hrp, "brx", hrplen);
    }
    
    // We set a lower bound to ensure this is safe
    if (out_len < hrplen + (in_len * 2) + 7) { // 7 is 6 bytes checksum and 1 byte delimiter (always "1")
        PRINTF("bech32 encoding failed, buffer too small.\n");
        return false;
    }

    // Overestimate required size *2==(8/4) instead of *(8/5)
    uint8_t tmp_data[MAX_INPUT_SIZE * 2];
    size_t tmp_size = 0;
    explicit_bzero(tmp_data, sizeof(tmp_data));

    convert_bits(tmp_data, &tmp_size, 5, in, in_len, 8, pad);
    if (tmp_size >= out_len) {
        PRINTF("bech32 encoding failed, out of bounds.\n");
        return false;
    }

    int err = bech32_encode(out, hrp, tmp_data, tmp_size);
    if (err == 0) {
        PRINTF("bech32 encoding failed, encoding failed.\n");
        return false;
    }

    return true;
}
