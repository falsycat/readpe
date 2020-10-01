#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pe.h"

typedef struct readpe_context_t {
  bool _64bit;

  size_t image_length;
  size_t header_length;

  uint8_t* image;

  const pe_dos_header_t* dos_header;

  const uint8_t* dos_stub;
  size_t         dos_stub_length;

  const pe_nt_header_t* nt_header;

  const pe_image_data_directory_t* data_directory;
  size_t                           data_directory_length;

  const pe_image_section_header_t* sections;

  const pe_image_export_directory_t* exports;
  size_t exports_section_length;
} readpe_context_t;

bool
readpe_context_initialize(
    readpe_context_t* ctx,
    const char* filename
);

void
readpe_context_deinitialize(
    readpe_context_t* ctx
);

bool
readpe_context_get_export_table(
    const readpe_context_t*             ctx,
    const pe_image_export_directory_t** table
);
