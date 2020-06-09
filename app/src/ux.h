#ifndef RADIX_TOKEN_NANOS_UX_H
#define RADIX_TOKEN_NANOS_UX_H

#include "radix.h"
#include "global_state.h"

extern ux_state_t ux;

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

// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

// io_exchange_with_code is a helper function for sending APDUs, primarily
// from button handlers. It appends code to G_io_apdu_buffer and calls
// io_exchange with the IO_RETURN_AFTER_TX flag. tx is the current offset
// within G_io_apdu_buffer (before the code is appended).
void io_exchange_with_code(uint16_t code, uint16_t tx);

#endif