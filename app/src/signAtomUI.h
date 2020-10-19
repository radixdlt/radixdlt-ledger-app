#ifndef SIGNATOMUI_H
#define SIGNATOMUI_H

#include "ui.h"
#include <stdbool.h>

bool finished_parsing_all_particles();

void ask_user_for_confirmation_of_transfer_if_to_other_address();
void ask_user_to_verify_hash_before_signing();
void ask_user_for_confirmation_of_non_transfer_data();

void ui_init_progress_display();
void ui_update_progress_display();

#endif