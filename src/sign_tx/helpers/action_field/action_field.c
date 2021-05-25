#include "action_field.h"
#include <os.h>
#include "common_macros.h"

static uint16_t populate_interval(
	byte_interval_t *interval,
	uint8_t *bytes
) {
	
	uint16_t offset = 0;
	interval->start_index_in_tx = U2BE(bytes, offset); offset += 2;
    interval->byte_count = U2BE(bytes, offset); offset += 2;
    return offset;
}

void print_action_field(action_field_t *field) {
    assert(field->is_destroyed == false);
    print_action_field_type(field->field_type);
    PRINTF(" ");
    print_interval(&field->byte_interval);
}


void initialize_action_field_with_bytes(
    action_field_t *field, 
    ActionFieldType field_type,
    uint8_t *bytes, uint16_t byte_count
) {
    assert(is_valid_action_field_type(field_type));
    assert(byte_count == 4);
    populate_interval(
        &field->byte_interval,
        bytes
    );
    field->field_type = field_type;
    field->is_destroyed = false;
    assert(field->byte_interval.byte_count > 0);
}
