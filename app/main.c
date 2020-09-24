#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "pe.h"

#include "./args.h"
#include "./output.h"

static bool readpe_read_and_output_(const readpe_args_t* args, FILE* fp) {
  assert(args != NULL);
  assert(fp   != NULL);

  pe_dos_header_t dos_header;
  if (fread(&dos_header, PE_DOS_HEADER_SIZE, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading dos header\n");
    return false;
  }
  if (dos_header.e_magic != PE_DOS_HEADER_MAGIC) {
    fprintf(stderr,
        "magic number in dos header is 0x%04"PRIX16", "
        "but expected 0x%04"PRIX16"\n",
        dos_header.e_magic,
        PE_DOS_HEADER_MAGIC);
    return false;
  }
  if (args->dos_header) readpe_output_dos_header(&dos_header);

  /* TODO(catfoot): */

  return true;
}

int main(int argc, char** argv) {
  readpe_args_t args;
  if (!readpe_args_parse(&args, argc, (const char**) argv)) {
    fprintf(stderr, "failed to parse args\n");
    return EXIT_FAILURE;
  }
  if (args.help) {
    readpe_args_print_help();
    return EXIT_SUCCESS;
  }

  FILE* fp = fopen(args.input, "rb");
  if (fp == NULL) {
    fprintf(stderr, "failed to open file: %s\n", args.input);
    return EXIT_FAILURE;
  }
  const bool ret = readpe_read_and_output_(&args, fp);
  fclose(fp);

  return ret? EXIT_SUCCESS: EXIT_FAILURE;
}
