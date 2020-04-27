#include "RadixAddress.h"
#include "RadixResourceIdentifier.h"
#include "Granularity.h"
#include "Planck.h"
#include "Nonce.h"

typedef struct {
    RadixAddress address;
    RadixResourceIdentifier tokenDefinitionReference;
    Granularity granularity;
    Planck planck;
    Nonce nonce;
    // permissions: TokenPermissions (skipped)
} TransferrableTokensParticle;