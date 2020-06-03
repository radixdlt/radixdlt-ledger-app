#ifndef RADIX_TOKEN_NANOS_UX_H
#define RADIX_TOKEN_NANOS_UX_H

#include "radix.h"
#include "global_state.h"

// ux is a magic global variable implicitly referenced by the UX_ macros. Apps
// should never need to reference it directly.
extern ux_state_t ux;

// These are helper macros for defining UI elements. There are four basic UI
// elements: the background, which is a black rectangle that fills the whole
// screen; icons on the left and right sides of the screen, typically used for
// navigation or approval; and text, which can be anywhere. The UI_TEXT macro
// uses Open Sans Regular 11px, which I've found to be adequate for all text
// elements; if other fonts are desired, I suggest defining a separate macro
// for each of them (e.g. UI_TEXT_BOLD).
//
// In the event that you want to define your own UI elements from scratch,
// you'll want to read include/bagl.h and include/os_io_seproxyhal.h in the
// nanos-secure-sdk repo to learn what each of the fields are used for.
#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL,0,0,0,NULL,NULL,NULL}

#define UI_ICON_LEFT_ID(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_LEFT(glyph) UI_ICON_LEFT_ID(0x00, glyph)
#define ICON_LEFT_ARROW UI_ICON_LEFT_ID(0x01, BAGL_GLYPH_ICON_LEFT)
#define ICON_CROSS_L UI_ICON_LEFT(BAGL_GLYPH_ICON_CROSS)

#define UI_ICON_RIGHT_ID(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
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
    \
    (char *)text, \
    0, \
    0, \
    0, \
    NULL, \
    NULL, \
    NULL \
}

#define TEXT_UPPER_ID(userid, text) UI_TEXT(userid, 0, 11, 128, text)
#define TEXT_UPPER(text) TEXT_UPPER_ID(0x00, text)
#define TEXT_LOWER_ID(userid, text) UI_TEXT(userid, 0, 26, 128, text)
#define TEXT_LOWER(text) TEXT_LOWER_ID(0x00, text)

#define APPROVAL_SCREEN_TWO_LINES(textLine1, textLine2) \
    {                                                   \
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