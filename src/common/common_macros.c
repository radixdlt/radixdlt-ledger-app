//
//  common_macros.c
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-24.
//

#include "common_macros.h"


// Returns true if error code was known, else false
bool print_error_by_code(int e) {
    switch (e) {
        case EXCEPTION: {
            PRINTF("error %d is 'EXCEPTION'\n", e);
            return true;
        }
        case INVALID_PARAMETER: {
            PRINTF("error %d is 'INVALID_PARAMETER'\n", e);
            return true;
        }
        case INVALID_STATE: {
            PRINTF("error %d is 'INVALID_STATE'\n", e);
            return true;
        }
        case EXCEPTION_OVERFLOW: {
            PRINTF("error %d is 'EXCEPTION_OVERFLOW'\n", e);
            return true;
        }
        case EXCEPTION_SECURITY: {
            PRINTF("error %d is 'EXCEPTION_SECURITY'\n", e);
            return true;
        }
        case EXCEPTION_CXPORT: {
             PRINTF("error %d is 'EXCEPTION_CXPORT'\n", e);
            return true;
        }

        case EXCEPTION_IO_OVERFLOW: {
              PRINTF("error %d is 'EXCEPTION_IO_OVERFLOW'\n", e);
            return true;
        }
        default: break;
    }
    PRINTF("error %d is not known.\n", e);
    return false;
}
