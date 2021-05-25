#include "actions_counter.h"
#include "common_macros.h"

static void print_left_to_identify(actions_counter_t *counter) {
    PRINTF("Identified %d/%d TTPs and %d/%d NON TTPs\n", counter->identified.transferrable_tokens_action, counter->in_tx.transferrable_tokens_action, counter->identified.non_transfer, counter->in_tx.non_transfer);
}

static uint8_t number_of_transferrable_tokens_actions_left_to_identify(
    actions_counter_t *counter
) {
    int left = ((int) counter->in_tx.transferrable_tokens_action) - ((int) counter->identified.transferrable_tokens_action);

    assert(left >= 0);

    return (uint8_t) left;
}

static uint8_t number_of_non_transferrable_tokens_actions_left_to_identify(
    actions_counter_t *counter
) {
    int left = ((int) counter->in_tx.non_transfer) - ((int) counter->identified.non_transfer);
    assert(left >= 0);
    return left;
}

static bool have_identified_all_up_transferrable_tokens_actions(actions_counter_t *counter) {
    bool have_identified_all_transfers = number_of_transferrable_tokens_actions_left_to_identify(counter) == 0;
    return have_identified_all_transfers;
}

static bool have_identified_all_non_up_transferrable_tokens_actions(actions_counter_t *counter) {
    bool have_identified_all_non_TTP = number_of_non_transferrable_tokens_actions_left_to_identify(counter) == 0;
    return have_identified_all_non_TTP;
}

void init_actions_counter(
    actions_counter_t *counter,
    uint8_t total_number_of_actions,
    uint8_t number_of_up_transferrable_tokens_actions
) {

    counter->in_tx.non_transfer = total_number_of_actions - number_of_up_transferrable_tokens_actions;
    counter->in_tx.transferrable_tokens_action = number_of_up_transferrable_tokens_actions;
 
    counter->identified.non_transfer = 0;
    counter->identified.transferrable_tokens_action = 0;

}

void identified_a_transferrable_tokens_action(
    actions_counter_t *counter
) {
    assert(!have_identified_all_up_transferrable_tokens_actions(counter));
    counter->identified.transferrable_tokens_action += 1;

    print_left_to_identify(counter);
}

void identified_a_non_transferrable_tokens_action(
    actions_counter_t *counter
) {
    assert(!have_identified_all_non_up_transferrable_tokens_actions(counter));
    counter->identified.non_transfer++;

    print_left_to_identify(counter);
}


bool has_identified_all_actions(
    actions_counter_t *counter
) {
    return have_identified_all_up_transferrable_tokens_actions(counter) && have_identified_all_non_up_transferrable_tokens_actions(counter);
}

uint8_t total_number_of_actions(action_count_t *count) {
    return count->transferrable_tokens_action + count->non_transfer;
}
