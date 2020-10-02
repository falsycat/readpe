#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "pe.h"

#include "./args.h"
#include "./context.h"
#include "./output.h"

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

  readpe_context_t ctx;
  if (!readpe_context_initialize(&ctx, args.input)) {
    return EXIT_FAILURE;
  }

  if (args.dos_header) {
    readpe_output_dos_header(ctx.dos_header);
  }
  if (args.dos_stub) {
    readpe_output_dos_stub(ctx.dos_stub, ctx.dos_stub_length);
  }
  if (args.nt_header) {
    readpe_output_nt_header(ctx.nt_header);
  }
  if (args.section_table) {
    readpe_output_section_table(ctx.sections, ctx.nt_header->file.number_of_sections);
  }
  if (args.export_table) {
    readpe_output_export_table(
        ctx.image, ctx.exports, ctx.exports_section_length);
  }
  if (args.relocation_table) {
    readpe_output_relocation_table(
        ctx.image, ctx.relocations, ctx.relocations_length);
  }

  readpe_context_deinitialize(&ctx);
  return EXIT_SUCCESS;
}
