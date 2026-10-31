#include "prx/libSceIcu/Identified.hpp"
#include <stdexcept>

namespace {

constexpr std::int32_t NotTerminated = -124;
constexpr std::int32_t BufferOverflow = 15;

}

extern "C" {

std::int32_t APS5_VABI u_terminateChars_nid_postfix(char* destination, std::int32_t capacity, std::int32_t length, std::int32_t* status) {
    if (!status || *status > 0 || length < 0) return length;
    if (length < capacity) {
        if (!destination) throw std::invalid_argument("ICU string termination: null destination");
        destination[length] = 0;
        if (*status == NotTerminated) *status = 0;
    } else {
        *status = length == capacity ? NotTerminated : BufferOverflow;
    }
    return length;
}

}
