#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pe.h"

typedef struct {
  bool _64bit;

  uint8_t* image;
  size_t   image_length;

  pe_dos_header_t* dos_header;

  uint8_t* dos_stub;
  size_t   dos_stub_length;

  pe_nt_header_t* nt_header;

  pe_image_section_header_t* sections;
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
