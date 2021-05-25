#ifndef ACTIONSCOUNTER_H
#define ACTIONSCOUNTER_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t non_transfer;
    uint8_t transferrable_tokens_action;
} action_count_t;

typedef struct {
    action_count_t in_tx;
    action_count_t identified;
} actions_counter_t;


void init_actions_counter(
    actions_counter_t *counter,
    uint8_t total_number_of_actions,
    uint8_t number_of_up_transferrable_tokens_actions
);

void identified_a_transferrable_tokens_action(
    actions_counter_t *counter
);

void identified_a_non_transferrable_tokens_action(
    actions_counter_t *counter
);

bool has_identified_all_actions(
    actions_counter_t *counter
);


uint8_t total_number_of_actions(action_count_t *count);


#endif
