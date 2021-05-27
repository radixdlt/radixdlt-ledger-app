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
#include "abstract_address.h"
#include "os.h"
#include "segwit_addr.h"

bool abstract_address_from_network_and_bytes(
    char *hrp,
    size_t hrplen,
                                    
    const uint8_t *in,
    size_t in_len,
                         
    bool should_pad,
                         
    char *out,
    size_t out_len
) {
    explicit_bzero(out, out_len);

    if (in_len > MAX_BECH32_DATA_PART_BYTE_COUNT) {
        PRINTF("bech32 encoding failed, out of bounds.\n");
        return false;
    }
    
    
    // We set a lower bound to ensure this is safe
    if (out_len < hrplen + (in_len * 2) + 7) { // 7 is 6 bytes checksum and 1 byte delimiter (always "1")
        PRINTF("bech32 encoding failed, buffer too small.\n");
        return false;
    }

    uint8_t tmp_data[MAX_BECH32_DATA_PART_BYTE_COUNT];
    size_t tmp_size = 0;
    explicit_bzero(tmp_data, sizeof(tmp_data));

    int pad = 0;
    if (should_pad) {
        pad = 1;
    }
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
