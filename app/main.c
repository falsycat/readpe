#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "pe.h"

#include "./args.h"
#include "./output.h"

#define MAX(a, b) ((a) > (b)? (a): (b))

static bool readpe_read_and_output_(const readpe_args_t* args, FILE* fp) {
  assert(args != NULL);
  assert(fp   != NULL);

  pe_dos_header_t dos_header;
  if (fread(&dos_header, PE_DOS_HEADER_SIZE, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading dos header\n");
    return false;
  }
  if (dos_header.e_magic != PE_DOS_MAGIC) {
    fprintf(stderr,
        "magic number in dos header is 0x%04"PRIX16", "
        "but expected 0x%04"PRIX16"\n",
        dos_header.e_magic,
        PE_DOS_MAGIC);
    return false;
  }
  if (args->dos_header) readpe_output_dos_header(&dos_header);

  if (args->dos_stub) {
    uint8_t dos_stub[64];

    size_t sz = dos_header.e_lfanew - PE_DOS_HEADER_SIZE;
    if (sz > sizeof(dos_stub)) sz = sizeof(dos_stub);
    if (fread(dos_stub, sz, 1, fp) != 1) {
      fprintf(stderr, "fread failed while reading dos stub\n");
      return false;
    }
    readpe_output_dos_stub(dos_stub, sizeof(dos_stub));
  }

  uint8_t nt_header[MAX(sizeof(pe32_nt_header_t), sizeof(pe64_nt_header_t))];
  fseek(fp, dos_header.e_lfanew, SEEK_SET);
  if (fread(&nt_header, offsetof(pe32_nt_header_t, optional), 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading signature and file header\n");
    return false;
  }

  const uint32_t signature = ((pe32_nt_header_t*) nt_header)->signature;
  if (signature != PE_IMAGE_SIGNATURE_NT) {
    fprintf(stderr,
        "image signature in nt header is 0x%08"PRIX32", "
        "but expected 0x%08"PRIX32"\n",
        signature,
        PE_IMAGE_SIGNATURE_NT);
    return false;
  }

  const uint16_t machine = ((pe32_nt_header_t*) nt_header)->file.machine;
  switch (machine) {
  case PE_IMAGE_FILE_MACHINE_I386:
    /* TODO(catfoot): */
    break;

  case PE_IMAGE_FILE_MACHINE_IA64:
  case PE_IMAGE_FILE_MACHINE_AMD64:
    /* TODO(catfoot): */
    break;

  default:
    fprintf(stderr,
        "machine code in file header is 0x%08"PRIX16", "
        "which is unknown\n",
        machine);
    return false;
  }

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
