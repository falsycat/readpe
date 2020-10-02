#pragma once

#include <stdbool.h>

typedef struct readpe_args_t {
  const char* input;

  bool help;
  bool all;

  bool dos_header;
  bool dos_stub;
  bool nt_header;

  bool section_table;
  bool export_table;
  bool relocation_table;
} readpe_args_t;

void
readpe_args_print_help(
    void
);

bool
readpe_args_parse(
    readpe_args_t*     args,
    int                argc,
    const char* const* argv
);
