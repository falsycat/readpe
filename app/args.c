#include "./args.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "thirdparty/parsarg-c/parsarg.h"

static bool readpe_args_parse_by_parsarg_(readpe_args_t* args, parsarg_t* pa) {
  assert(args != NULL);
  assert(pa   != NULL);

  *args = (typeof(*args)) {0};

  while (!parsarg_finished(pa)) {
    size_t nlen;
    const char* n = parsarg_pop_name(pa, &nlen);
    const char* v = parsarg_pop_value(pa);

    if (n != NULL) {
      bool ok = false;

#     define streq_(v) (strncmp(n, v, nlen) == 0 && v[nlen] == 0)
#     define bool_(name, arg_name) do {  \
        if (!ok && streq_(arg_name)) {  \
          if (v != NULL) {  \
            fprintf(stderr, "option '%s' cannot take values\n", arg_name);  \
            return false;  \
          }  \
          args->name = true;  \
          ok = true;  \
        }  \
      } while (0)

      bool_(help, "help");
      bool_(all,  "all");

      bool_(dos_header, "dos-header");
      bool_(dos_stub,   "dos-stub");
      bool_(nt_header,  "nt-header");

      bool_(section_table, "section-table");
      bool_(export_table,  "export-table");
      bool_(import_table,  "import-table");
      bool_(relocation_table,  "relocation-table");

#     undef bool_
#     undef streq_

      if (!ok) {
        fprintf(stderr, "unknown option: %.*s\n", (int) nlen, n);
        return false;
      }
    } else {

      if (args->input != NULL) {
        fprintf(stderr, "cannot take two input files\n");
        return false;
      }
      args->input = v;
    }
  }

  return true;
}

static void readpe_args_normalize_(readpe_args_t* args) {
  assert(args != NULL);

  args->dos_header |= args->all;
  args->dos_stub   |= args->all;
  args->nt_header  |= args->all;

  args->section_table    |= args->all;
  args->export_table     |= args->all;
  args->import_table     |= args->all;
  args->relocation_table |= args->all;
}

static bool readpe_args_validate_(const readpe_args_t* args) {
  assert(args != NULL);

  return
      (args->help || args->input != NULL);
}

void readpe_args_print_help(void) {
  printf("usage: readpe <exe file> [options]\n");
  printf("  options:\n");
  printf("    --all\n");
  printf("    --dos-header\n");
  printf("    --dos-stub\n");
  printf("    --nt-header\n");
  printf("    --section-table\n");
  printf("    --export-table\n");
  printf("    --relocation-table\n");
}

bool readpe_args_parse(readpe_args_t* args, int argc, const char* const* argv) {
  assert(args != NULL);

  parsarg_t pa;
  parsarg_initialize(&pa, argc-1, (char**) argv+1);

  const bool ret = readpe_args_parse_by_parsarg_(args, &pa);
  parsarg_deinitialize(&pa);
  if (!ret) return false;

  readpe_args_normalize_(args);
  return readpe_args_validate_(args);
}
