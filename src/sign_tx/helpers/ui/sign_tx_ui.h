#ifndef SIGNTXUI_H
#define SIGNTXUI_H

#include "ui.h"
#include <stdbool.h>

bool finished_parsing_all_actions(void);

void ask_user_for_confirmation_of_action(void);
void ask_user_to_verify_hash_before_signing(void);

void ui_init_progress_display(void);
void ui_update_progress_display(void);

#endif
