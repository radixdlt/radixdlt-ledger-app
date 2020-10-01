#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"

typedef struct {
    bool has_confirmed_serializer;
    RadixAddress address;
    TokenAmount amount;
    RadixResourceIdentifier token_definition_reference;
} Transfer;