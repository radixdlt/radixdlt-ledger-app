#include "RadixAddress.h"
#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"
// #include "Granularity.h"
// #include "Planck.h"
// #include "Nonce.h"

typedef struct {
    RadixAddress address;
    TokenAmount amount;
    RadixResourceIdentifier tokenDefinitionReference;
} Transfer;