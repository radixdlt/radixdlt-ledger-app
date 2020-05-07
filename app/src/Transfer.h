#include "RadixAddress.h"
#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"
// #include "Granularity.h"
// #include "Planck.h"
// #include "Nonce.h"

typedef struct {
    RadixAddress address;
    RadixResourceIdentifier tokenDefinitionReference;
    TokenAmount amount;
    // Granularity granularity;
    // Planck planck;
    // Nonce nonce;
} Transfer;