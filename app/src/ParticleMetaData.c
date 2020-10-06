#include "ParticleMetaData.h"

uint16_t end_index(ByteInterval interval) {
    return interval.startsAt + interval.byteCount;
}

uint16_t last_byte_of_particle_from_its_meta_data(ParticleMetaData particle_meta_data) {
    assert(particle_meta_data.is_initialized);
    return end_index(particle_meta_data.particleItself);
}
