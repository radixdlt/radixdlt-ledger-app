#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "deserialize_DER_signature.h"

/**
 * Parses a DER encoded signature and returns a 64 byte buffer of R & S.
 * Copied from Hanskake:
 * https://github.com/handshake-org/ledger-app-hns/blob/1bc8653b959ed33d26e82d3157f32a0c5ae3dd3c/src/ledger.c#L243-L384
 * 
 * Based on:
 * https://github.com/bitcoin-core/secp256k1/blob/abe2d3e/src/ecdsa_impl.h#L145
 *
 * In:
 * @param der is the DER encoded signature.
 * @param der_len is the length of the DER encoded signature.
 * @param sig_sz is the size of the signature buffer.
 *
 * Out:
 * @param sig is the decoded signature.
 * @return a boolean indicating success or failure.
 */
bool parse_der(uint8_t *der, uint8_t der_len, volatile uint8_t *sig, uint8_t sig_sz)
{
  if (der == NULL || der_len < 70 || der_len > 72)
  {
    PRINTF("\nDER DECODE FAIL - incorrect length of der\n");
    return false;
  }

  if (sig == NULL || sig_sz < 64)
  {
    PRINTF("\nDER DECODE FAIL - incorrect length of sig\n");
    return false;
  }

  uint8_t const *der_end = der + der_len;
  int overflow = 0;
  int len = 0;

  /* Prepare signature for padding. */
  memset(sig, 0, sig_sz);

  /* Check initial byte for correct format. */
  if (der == der_end || *(der++) != 0x30) {
    PRINTF("\nDER DECODE FAIL - incorrect format first byte\n");
    return false;
  }

  /* Check length of remaining data. */
  len = *(der++);

  if ((len & 0x80) != 0x00)
  {
    PRINTF("\nDER DECODE FAIL: ((len & 0x80) != 0x00)");
    return false;
  }

  if (len <= 0 || der + len > der_end)
  {
    PRINTF("\nDER DECODE FAIL: (len <= 0 || der + len > der_end)");
    return false;
  }

  if (der + len != der_end)
  {
    PRINTF("\nDER DECODE FAIL: (der + len != der_end)");
    return false;
  }

  /* Check tag byte for R. */
  if (der == der_end || *(der++) != 0x02)
  {
    PRINTF("\nDER DECODE FAIL: (der == der_end || *(der++) != 0x02)");
    return false;
  }

  /* Check length of R. */
  len = *(der++);

  if ((len & 0x80) != 0)
  {
    PRINTF("\nDER DECODE FAIL: ((len & 0x80) != 0) ");
    return false;
  }

  if (len <= 0 || der + len > der_end)
  {
    PRINTF("\nDER DECODE FAIL:  (len <= 0 || der + len > der_end)  ");
    return false;
  }

  /* Check padding of R. */

  /* Excessive 0x00 padding. */
  if (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00)
  {
    PRINTF("\nDER DECODE FAIL:  (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00) ");
    return false;
  }

  /* Excessive 0xff padding. */
  if (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80)
  {
    PRINTF("\nDER DECODE FAIL: (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80) ");
    return false;
  }

  /* Check sign of the length. */
  if ((der[0] & 0x80) == 0x80)
    overflow = 1;

  /* Skip leading zero bytes. */
  while (len > 0 && der[0] == 0)
  {
    len--;
    der++;
  }

  if (len > 32)
    overflow = 1;

  if (!overflow)
    memmove(sig + 32 - len, der, len);

  if (overflow)
    memset(sig, 0, 32);

  der += len;
  sig += 32;
  overflow = 0;

  /* Check tag byte for S. */
  if (der == der_end || *(der++) != 0x02)
  {

    PRINTF("\nDER DECODE FAIL: (der == der_end || *(der++) != 0x02) ");
    return false;
  }

  /* Check length of S. */
  len = *(der++);

  if ((len & 0x80) != 0)
  {
    PRINTF("\nDER DECODE FAIL:  ((len & 0x80) != 0)");
    return false;
  }

  if (len <= 0 || der + len > der_end)
  {
    PRINTF("\nDER DECODE FAIL:  (len <= 0 || der + len > der_end)");
    return false;
  }

  /* Check padding of S. */

  /* Excessive 0x00 padding. */
  if (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00)
  {
    PRINTF("\nDER DECODE FAIL:  (der[0] == 0x00 && len > 1 && (der[1] & 0x80) == 0x00)");
    return false;
  }

  /* Excessive 0xff padding. */
  if (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80)
  {
    PRINTF("\nDER DECODE FAIL:  (der[0] == 0xff && len > 1 && (der[1] & 0x80) == 0x80) ");
    return false;
  }

  /* Check sign of the length. */
  if ((der[0] & 0x80) == 0x80)
    overflow = 1;

  /* Skip leading zero bytes. */
  while (len > 0 && der[0] == 0)
  {
    len--;
    der++;
  }

  if (len > 32)
    overflow = 1;

  if (!overflow)
    memmove(sig + 32 - len, der, len);

  if (overflow)
    memset(sig, 0, 32);

  der += len;
  sig += 32;

  if (der != der_end)
  {
    PRINTF("\nDER DECODE FAIL:  (der != der_end)");
    return false;
  }

  PRINTF("\nDER DECODE SUCCESSFULL\n");
  return true;
}
