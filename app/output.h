#pragma once

#include <stddef.h>
#include <stdint.h>

#include "pe.h"

void
readpe_output_dos_header(
    const pe_dos_header_t* dos_header
);

void
readpe_output_dos_stub(
    const uint8_t* body,
    size_t         len
);
