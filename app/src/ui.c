#include "ui.h"
#include <os_io_seproxyhal.h>
#include "common_macros.h"


#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL}

// #define UI_ICON_LEFT_ID(userid, glyph) (bagl_element_t*) { \ /* bagl_component_t */
//     .component = (bagl_element_e) { \
//         .type = BAGL_ICON, \    /* bagl_components_type_e   */
//         .userid = userid, \     /* unsigned char            */
//         .x = 3, \               /* short <-- "allow for out of screen rendering" */
//         .y = 12, \              /* short <-- "allow for out of screen rendering" */
//         .width = 7, \           /* unsigned short */
//         .height = 7, \          /* unsigned short */
//         .stroke = 0, \          /* unsigned char */
//         .radius = 0, \          /* unsigned char */
//         .fill = 0, \            /* unsigned char */
//         .fgcolor = 0xFFFFFF, \  /* unsigned int <-- Foreground color */
//         .bgcolor = 0, \         /* unsigned int <-- Background color */
//         .font_id = 0, \         /* unsigned short  */
//         .icon_id = glyph \      /* unsigned char */
//     }, \
//     .text = NULL \              /* const char*              */
// }

#define UI_ICON_LEFT_ID(userid, glyph) { \
    { \
        BAGL_ICON, \
        userid, \
        3, \
        12, \
        7, \
        7, \
        0, \
        0, \
        0, \
        0xFFFFFF, \
        0, \
        0, \
        glyph \
    }, \
    NULL \
}

#define UI_ICON_LEFT(glyph) UI_ICON_LEFT_ID(0x00, glyph)
#define ICON_LEFT_ARROW UI_ICON_LEFT_ID(0x01, BAGL_GLYPH_ICON_LEFT)
#define ICON_CROSS_L UI_ICON_LEFT(BAGL_GLYPH_ICON_CROSS)

#define UI_ICON_RIGHT_ID(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL}
#define UI_ICON_RIGHT(glyph) UI_ICON_RIGHT_ID(0x00, glyph)
#define ICON_RIGHT_ARROW UI_ICON_RIGHT_ID(0x02, BAGL_GLYPH_ICON_RIGHT)
#define ICON_CHECK_R UI_ICON_RIGHT(BAGL_GLYPH_ICON_CHECK)

#define UI_TEXT(userid, x, y, w, text) { \
    { \
        BAGL_LABELINE, \
        userid, \
        x, \
        y, \
        w, \
        12, \
        0, \
        0, \
        0, \
        0xFFFFFF, \
        0, \
        BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, \
        0 \
    }, \
    (char *)text\
}

#define TEXT_UPPER_ID(userid, text) UI_TEXT(userid, 0, 11, 128, text)
#define TEXT_UPPER(text) TEXT_UPPER_ID(0x00, text)
#define TEXT_LOWER_ID(userid, text) UI_TEXT(userid, 0, 26, 128, text)
#define TEXT_LOWER(text) TEXT_LOWER_ID(0x00, text)

#define TEXT_TWO_LINES(textLine1, textLine2) { \
        UI_BACKGROUND(),                                \
        TEXT_UPPER(textLine1),           \
        TEXT_LOWER(textLine2),           \
}

#define APPROVAL_SCREEN_TWO_LINES(textLine1, textLine2) { \
        UI_BACKGROUND(),                                \
        ICON_CROSS_L,                                   \
        ICON_CHECK_R,                                   \
        TEXT_UPPER(textLine1),           \
        TEXT_LOWER(textLine2),           \
}

#define SEEK_SCREEN_TWO_LINES(textLine1, textLine2) \
    {                                               \
        UI_BACKGROUND(),                            \
        ICON_LEFT_ARROW,                            \
        ICON_RIGHT_ARROW,                           \
        TEXT_UPPER(textLine1),           \
        TEXT_LOWER(textLine2),           \
}


#define APPROVAL_SCREEN(textLine1) APPROVAL_SCREEN_TWO_LINES(textLine1, G_ui_state.lower_line_short)
#define SEEK_SCREEN(textLine1) SEEK_SCREEN_TWO_LINES(textLine1, G_ui_state.lower_line_short)

ui_state_t G_ui_state;

void clear_lower_line_long() {
    os_memset(G_ui_state.lower_line_long, 0x00, MAX_LENGTH_FULL_STR_DISPLAY);
    G_ui_state.length_lower_line_long = 0;
}

void clear_partialStr() {
    os_memset(G_ui_state.lower_line_short, 0x00,
              DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    G_ui_state.lower_line_display_offset = 0;
}

void reset_ui() { 
    clear_lower_line_long();
    clear_partialStr();
 }

static void ui_fullStr_to_partial() {
    clear_partialStr();

    os_memmove(G_ui_state.lower_line_short, G_ui_state.lower_line_long,
               DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    G_ui_state
        .lower_line_short[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] =
        '\0';
}

static callback_t function_pointer;

unsigned int reject_or_approve(unsigned int button_mask,
                               unsigned int button_mask_counter,
                               callback_t didApproveCallback) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: {  // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {  // Approve
            didApproveCallback();
            break;
        }
    }
    return 0;
}

unsigned int seek_left_right_or_approve(unsigned int button_mask,
                                        unsigned int button_mask_counter,
                                        callback_t didApproveCallback) {
    switch (button_mask) {
        case BUTTON_LEFT:
        case BUTTON_EVT_FAST | BUTTON_LEFT:  // SEEK LEFT
            // Decrement the lower_line_display_offset when the left button is pressed (or
            // held).
            if (G_ui_state.lower_line_display_offset > 0) {
                G_ui_state.lower_line_display_offset--;
            }
            os_memmove(G_ui_state.lower_line_short,
                       G_ui_state.lower_line_long + G_ui_state.lower_line_display_offset,
                       DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
            // Re-render the screen.
            UX_REDISPLAY();
            break;

        case BUTTON_RIGHT:
        case BUTTON_EVT_FAST | BUTTON_RIGHT:  // SEEK RIGHT
            if (G_ui_state.lower_line_display_offset <
                (G_ui_state.length_lower_line_long -
                 DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)) {
                G_ui_state.lower_line_display_offset++;
            }
            os_memmove(G_ui_state.lower_line_short,
                       G_ui_state.lower_line_long + G_ui_state.lower_line_display_offset,
                       DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
            UX_REDISPLAY();
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:  // PROCEED
            didApproveCallback();
            break;
    }
    return 0;
}

const bagl_element_t *preprocessor_for_seeking(const bagl_element_t *element) {
    if ((element->component.userid == 1 && G_ui_state.lower_line_display_offset == 0) ||
        (element->component.userid == 2 &&
         (G_ui_state.lower_line_display_offset ==
          (G_ui_state.length_lower_line_long -
           DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)))) {
        return NULL;
    }
    return element;
}

static char title_row_one[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE +
                          1];  // +1 for null
static char title_row_two[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE +
                          1];  // +1 for null

static const bagl_element_t ui_generic_single_line_approve[] =
    APPROVAL_SCREEN(title_row_one);

static unsigned int ui_generic_single_line_approve_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter,
                             function_pointer);
}

static const bagl_element_t ui_generic_single_line_seek[] =
    SEEK_SCREEN(title_row_one);

static unsigned int ui_generic_single_line_seek_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter,
                                      function_pointer);
}

static const bagl_element_t ui_generic_two_lines_approve[] =
    APPROVAL_SCREEN_TWO_LINES(title_row_one, title_row_two);

static unsigned int ui_generic_two_lines_approve_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter,
                             function_pointer);
}

static void display(const char *row_1_max_12_chars,
                    const char *row_2_max_12_chars,
                    callback_t didApproveCallback) {
    if (!row_1_max_12_chars) {
        FATAL_ERROR("First row cannot be null");
    }

    function_pointer = didApproveCallback;

    int length_of_row1 = strlen(row_1_max_12_chars);
    assert(length_of_row1 <= DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);

    os_memset(title_row_one, 0x00,
              DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    os_memcpy(title_row_one, row_1_max_12_chars, length_of_row1);
    title_row_one[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';

    os_memset(title_row_two, 0x00,
              DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);

    ui_fullStr_to_partial();

    if (row_2_max_12_chars) {
        int length_of_row2 = strlen(row_2_max_12_chars);
        assert(length_of_row2 <= DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
        os_memcpy(title_row_two, row_2_max_12_chars, length_of_row2);
        title_row_two[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';

        UX_DISPLAY(ui_generic_two_lines_approve, NULL);
    } else {
        // single line

        if (G_ui_state.length_lower_line_long >
            DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE) {
            UX_DISPLAY(ui_generic_single_line_seek, preprocessor_for_seeking);
        } else {
            UX_DISPLAY(ui_generic_single_line_approve, NULL);
        }
    }
}

void display_lines(const char *row_1_max_12_chars,
                   const char *row_2_max_12_chars,
                   callback_t didApproveCallback) {
    if (!row_2_max_12_chars) {
        FATAL_ERROR("Second row cannot be null");
    }

    display(row_1_max_12_chars, row_2_max_12_chars, didApproveCallback);
}

void display_value(const char *title_max_12_chars,
                   callback_t didApproveCallback) {
    display(title_max_12_chars, NULL, didApproveCallback);
}
