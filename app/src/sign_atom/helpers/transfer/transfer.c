#include "transfer.h"


void print_transfer(transfer_t *transfer) {
    PRINTF("\n\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    PRINTF("transfer_t(\n");
    PRINTF("    Address b58: "); printRadixAddress(&transfer->address); PRINTF("\n");
    PRINTF("    Amount (dec): "), print_token_amount(&transfer->amount); PRINTF(" E-18\n");
    PRINTF("    Token symbol: "); print_radix_resource_identifier(&transfer->token_definition_reference); PRINTF("\n");
    PRINTF(")\n");
    PRINTF("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n\n");
}