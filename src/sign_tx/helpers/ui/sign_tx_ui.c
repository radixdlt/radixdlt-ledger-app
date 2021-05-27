#include "sign_tx_ui.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "base_conversion.h"
#include "common_macros.h"



static sign_tx_context_t *ctx = &global.sign_tx_context;

typedef enum {
    ReviewActionType = 0,
    ReviewFromAccountAddress,
    ReviewToAddress_Account,
    ReviewToAddress_Validator,
    ReviewAmount,
    ReviewRRI
} ReviewActionStep;


// // ===== START ===== HELPERS =========

static void prepare_display_with_transfer_data_step(ReviewActionStep step)
{
    clear_lower_line_long();
    action_t *action = &ctx->parse_state.action;

    switch (step)
    {
        case ReviewActionType: {
            
            char *action_type_str = to_string_action_type(action->action_type);
            uint8_t len = (uint8_t) strlen(action_type_str);
            G_ui_state.length_lower_line_long = len;
            os_memcpy(G_ui_state.lower_line_long, action_type_str, len);
            break;
        }
            
        case ReviewFromAccountAddress: {
            size_t number_of_chars_to_copy = ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;
            assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
            G_ui_state.length_lower_line_long = to_string_account_address(&action->from, G_ui_state.lower_line_long, number_of_chars_to_copy);
            break;
        }
        case ReviewToAddress_Account: {
            size_t number_of_chars_to_copy = ACCOUNT_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;
            assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
            G_ui_state.length_lower_line_long = to_string_account_address(&action->to_u.account_address, G_ui_state.lower_line_long, number_of_chars_to_copy);
            break;
        }
        case ReviewToAddress_Validator: {
            size_t number_of_chars_to_copy = VALIDATOR_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;
            assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
            
            G_ui_state.length_lower_line_long = to_string_validator_address(&action->to_u.validator_address, G_ui_state.lower_line_long, number_of_chars_to_copy);
            break;
        }

    case ReviewAmount:
    {
        size_t number_of_chars_to_copy = UINT256_DEC_STRING_MAX_LENGTH + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
       G_ui_state.length_lower_line_long = to_string_uint256(&action->amount, G_ui_state.lower_line_long, number_of_chars_to_copy);
        break;
    }
    case ReviewRRI: {

        size_t offset = to_string_rri_null_term_or_not(
            &action->rri,
            G_ui_state.lower_line_long, 
            RADIX_RRI_MAX_LENGTH_SYMBOL, 
            true,
            false
        );

        size_t length_of_string___comma_space_Full_Identifier_color_space = 19;
        os_memcpy(
            G_ui_state.lower_line_long + offset,
            ", Full Identifier: ",
            length_of_string___comma_space_Full_Identifier_color_space
        );
        offset += length_of_string___comma_space_Full_Identifier_color_space;

        offset += to_string_rri_null_term_or_not(
            &action->rri,
            G_ui_state.lower_line_long + offset, 
            MAX_LENGTH_FULL_STR_DISPLAY - offset,
            false,
            true
        );

       G_ui_state.length_lower_line_long = offset;
        break;
    }
    default:
        FATAL_ERROR("Unknown step: %d", step);
    }
}
// ===== END ===== HELPERS =========


static void do_ask_user_for_confirmation_of_signing_hash(void);

static void prepare_for_displaying_of_hash(void) {
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL
    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.lower_line_long);
    G_ui_state.length_lower_line_long = lengthOfHashString;
}

bool finished_parsing_all_actions(void);

static bool finished_parsing_whole_tx() {
    return ctx->number_of_tx_bytes_received == ctx->tx_byte_count && finished_parsing_all_actions();
}


void ui_update_progress_display(void);
static void redisplay_progress() {
    ui_init_progress_display();
}

static void unblock_ux(int tx) {
    io_exchange_with_code(SW_OK, tx);

    if (finished_parsing_whole_tx()) {
        ui_idle();
    } else {
        redisplay_progress();
    }
}

static void continue_sign_tx_flow(void) {
    unblock_ux(0);
}

static void did_approve_signing_of_hash(void) {

    int tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
    assert(tx == ECSDA_SIGNATURE_BYTE_COUNT);

    PRINTF("Signed tx, resulting signature: %.*h\n", ECSDA_SIGNATURE_BYTE_COUNT, G_io_apdu_buffer);
    PRINTF("\n\n._-=~$#@   END OF SIGN TX   @#$=~-_.\n\n");
    
	unblock_ux(tx);
}

static void finished_approving_action(void) {
    continue_sign_tx_flow();
}

static void did_approve_rri(void) {
    finished_approving_action();
}

static void prepare_for_approval_of_rri(void)
{
    prepare_display_with_transfer_data_step(ReviewRRI);
    display_value("Token:", did_approve_rri);
}

static void prepare_for_approval_of_amount(void) {
    prepare_display_with_transfer_data_step(ReviewAmount);
    
    callback_t cb = NULL;
    switch (ctx->parse_state.action.action_type) {
        case ActionTypeTransferTokens: {
            cb = prepare_for_approval_of_rri;
            break;
        }
        case ActionTypeStakeTokens:
        case ActionTypeUnstakeTokens:
            // N.B. for stake and unstake, the RRI is always XRD, so we do not display it.
            cb = finished_approving_action;
            break;
        case ActionTypeNotSet:
        default:
            FATAL_ERROR("Unknown of not set action type");
            ui_idle();
            return;
    }
    
    display_value("Amount:", cb);
}

static void prepare_for_approval_to_account(void) {
    prepare_display_with_transfer_data_step(ReviewToAddress_Account);
    display_value("To account:", prepare_for_approval_of_amount);
}
static void prepare_for_approval_to_validator(void) {
    prepare_display_with_transfer_data_step(ReviewToAddress_Validator);
    display_value("To validator", prepare_for_approval_of_amount);
}

static void prepare_for_approval_action_type(void) {
    prepare_display_with_transfer_data_step(ReviewActionType);
    callback_t cb = NULL;
    switch (ctx->parse_state.action.action_type) {
        case ActionTypeTransferTokens: {
            // N.B. we skip FROM...
            cb = prepare_for_approval_to_account;
            break;
        }
        case ActionTypeStakeTokens:
        case ActionTypeUnstakeTokens:
            cb = prepare_for_approval_to_validator;
            break;
        case ActionTypeNotSet:
        default:
            FATAL_ERROR("Unknown of not set action type");
            ui_idle();
            return;
    }
    display_value("Action:", cb);
}


static void do_ask_user_for_confirmation_of_signing_hash() {
    display_lines("Sign content", "Confirm?", did_approve_signing_of_hash);
}

static unsigned short ux_visible_element_index = 0;

static const ux_menu_entry_t ui_hack_as_menu_progress_update[] = {
	{NULL, NULL, 0, NULL, "Parsing tx", G_ui_state.lower_line_short, 0, 0},
	UX_MENU_END,
};


bool finished_parsing_all_actions(void) {
    return ctx->parse_state.actions_parsed == ctx->parse_state.actions_to_parse;
}

void ask_user_to_verify_hash_before_signing(void) {
    prepare_for_displaying_of_hash();
    display_value("Verify Hash", do_ask_user_for_confirmation_of_signing_hash);
}

void ask_user_for_confirmation_of_action(void) {
    display_lines("Review", "action", prepare_for_approval_action_type);
}

void ui_init_progress_display(void) {
    UX_MENU_DISPLAY(0, ui_hack_as_menu_progress_update, NULL);
    ux_visible_element_index = G_ux.stack[0].element_index;
    ui_update_progress_display();
}


void ui_update_progress_display(void) {
    reset_ui();

    size_t percentage = (100 * ctx->number_of_tx_bytes_received / ctx->tx_byte_count);

    snprintf(
        G_ui_state.lower_line_short, 
        DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
        "%02d%% done.", percentage
    );

    UX_REDISPLAY_IDX(ux_visible_element_index);
}
