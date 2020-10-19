#include "Transfer.h"


void print_transfer(Transfer *transfer) {
    PRINTF("\n\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    PRINTF("Transfer(\n");
    PRINTF("    Address b58: "); printRadixAddress(&transfer->address); PRINTF("\n");
    PRINTF("    Amount (dec): "), printTokenAmount(&transfer->amount); PRINTF(" E-18\n");
    PRINTF("    Token symbol: "); printRRI(&transfer->token_definition_reference); PRINTF("\n");
    PRINTF(")\n");
    PRINTF("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n\n");
}