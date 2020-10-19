#include "particles_counter.h"
#include "common_macros.h"

static void print_left_to_identify(particles_counter_t *counter) {
    PRINTF("Identified %d/%d TTPs and %d/%d NON TTPs\n", counter->identified.transferrable_tokens_particle, counter->in_atom.transferrable_tokens_particle, counter->identified.non_transfer, counter->in_atom.non_transfer);
}

static uint8_t number_of_transferrable_tokens_particles_left_to_identify(
    particles_counter_t *counter
) {
    int left = ((int) counter->in_atom.transferrable_tokens_particle) - ((int) counter->identified.transferrable_tokens_particle);

    assert(left >= 0);

    return (uint8_t) left;
}

static uint8_t number_of_non_transferrable_tokens_particles_left_to_identify(
    particles_counter_t *counter
) {
    int left = ((int) counter->in_atom.non_transfer) - ((int) counter->identified.non_transfer);
    assert(left >= 0);
    return left;
}

static bool have_identified_all_up_transferrable_tokens_particles(particles_counter_t *counter) {
    bool have_identified_all_transfers = number_of_transferrable_tokens_particles_left_to_identify(counter) == 0;
    return have_identified_all_transfers;
}

static bool have_identified_all_non_up_transferrable_tokens_particles(particles_counter_t *counter) {
    bool have_identified_all_non_TTP = number_of_non_transferrable_tokens_particles_left_to_identify(counter) == 0;
    return have_identified_all_non_TTP;
}

void init_particles_counter(
    particles_counter_t *counter,
    uint8_t total_number_of_up_particles,
    uint8_t number_of_up_transferrable_tokens_particles
) {
    uint8_t number_of_non_transferrable_tokens_particles = total_number_of_up_particles - number_of_up_transferrable_tokens_particles;

    counter->in_atom.non_transfer = number_of_non_transferrable_tokens_particles;
    counter->in_atom.transferrable_tokens_particle = number_of_up_transferrable_tokens_particles;
 
    counter->identified.non_transfer = 0;
    counter->identified.transferrable_tokens_particle = 0;

}

void identified_a_transferrable_tokens_particle(
    particles_counter_t *counter
) {
    assert(!have_identified_all_up_transferrable_tokens_particles(counter));
    counter->identified.transferrable_tokens_particle += 1;

    print_left_to_identify(counter);
}

void identified_a_non_transferrable_tokens_particle(
    particles_counter_t *counter
) {
    assert(!have_identified_all_non_up_transferrable_tokens_particles(counter));
    counter->identified.non_transfer++;

    print_left_to_identify(counter);
}


bool has_identified_all_particles(
    particles_counter_t *counter
) {
    return have_identified_all_up_transferrable_tokens_particles(counter) && have_identified_all_non_up_transferrable_tokens_particles(counter);
}