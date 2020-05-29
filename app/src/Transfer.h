#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"

typedef struct {
    RadixAddress address;
    TokenAmount amount;
    RadixResourceIdentifier tokenDefinitionReference;
} Transfer;