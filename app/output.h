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

void
readpe_output_nt_header(
    const pe_nt_header_t* header
);

void
readpe_output_section_table(
    const pe_image_section_header_t* table,
    size_t                           rows
);

void
readpe_output_export_table(
    const uint8_t*                     img,
    const pe_image_export_directory_t* table,
        /* NULLABLE, a pointer to an entity in the img */
    size_t                             section_length
);
