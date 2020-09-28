#include "./context.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pe.h"

static bool readpe_context_copy_image_on_memory_(
    readpe_context_t* ctx, FILE* fp) {
  assert(ctx != NULL);
  assert(fp  != NULL);

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
  fseek(fp, dos_header.e_lfanew, SEEK_SET);

  pe_nt_header_t nt_header = {0};
  if (fread(&nt_header.signature, sizeof(nt_header.signature), 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading signature\n");
    return false;
  }
  if (nt_header.signature != PE_IMAGE_SIGNATURE_NT) {
    fprintf(stderr,
        "image signature in nt header is 0x%04"PRIX16", "
        "but expected 0x%04"PRIX16"\n",
        nt_header.signature,
        PE_IMAGE_SIGNATURE_NT);
  }

  if (fread(&nt_header.file, PE_IMAGE_FILE_HEADER_SIZE, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading image file header\n");
    return false;
  }

  if (fread(&nt_header.optional,
        nt_header.file.size_of_optional_header, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading image optional header\n");
    return false;
  }

  switch (nt_header.file.machine) {
  case PE_IMAGE_FILE_MACHINE_I386:
    ctx->image_length = nt_header.optional._32bit.size_of_image;
    break;
  case PE_IMAGE_FILE_MACHINE_AMD64:
  case PE_IMAGE_FILE_MACHINE_IA64:
    ctx->_64bit = true;
    ctx->image_length = nt_header.optional._64bit.size_of_image;
    break;
  default:
    fprintf(stderr,
        "unknown machine code: 0x%04"PRIX16"\n", nt_header.file.machine);
    return false;
  }

  if (ctx->image_length == 0) {
    fprintf(stderr, "invalid image optional header: size_of_image is 0\n");
    return false;
  }

  ctx->image = malloc(ctx->image_length);
  fseek(fp, 0, SEEK_SET);
  if (fread(ctx->image, ctx->image_length, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading whole of the image\n");
    return false;
  }
  return true;
}

static bool readpe_context_find_addresses_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  const uint8_t* image_end = ctx->image + ctx->image_length;

  /* ---- dos header ---- */
  ctx->dos_header = (pe_dos_header_t*) ctx->image;

  if (ctx->image_length < PE_DOS_HEADER_SIZE) {
    fprintf(stderr, "invalid dos header: ends unexpectedly");
    return false;
  }

  /* ---- dos stub ---- */
  ctx->dos_stub        = ctx->image + PE_DOS_HEADER_SIZE;
  ctx->dos_stub_length = ctx->dos_header->e_lfanew - PE_DOS_HEADER_SIZE;

  if (ctx->dos_header->e_lfanew < PE_DOS_HEADER_SIZE ||
      (uintptr_t) ctx->dos_header->e_lfanew > ctx->image_length) {
    fprintf(stderr, "invalid dos stub: ends unexpectedly\n");
    return false;
  }

  /* ---- nt header ---- */
  ctx->nt_header = (pe_nt_header_t*) (ctx->image + ctx->dos_header->e_lfanew);

  if ((uint8_t*) &ctx->nt_header->file > image_end) {
    fprintf(stderr, "invalid image signature: ends unexpectedly\n");
    return false;
  }
  if ((uint8_t*) &ctx->nt_header->optional > image_end) {
    fprintf(stderr, "invalid image file header: ends unexpectedly\n");
    return false;
  }

  const uint8_t* image_optional_header_end;
  if (ctx->_64bit) {
    const uint8_t* number_of_rva_and_sizes_end =
        (uint8_t*) (&ctx->nt_header->optional._64bit.number_of_rva_and_sizes+1);
    if (number_of_rva_and_sizes_end > image_end) {
      image_optional_header_end = image_end + 1;
    } else {
      image_optional_header_end =
          (uint8_t*) &ctx->nt_header->optional._64bit.data_directory +
          ctx->nt_header->optional._64bit.number_of_rva_and_sizes*
          PE_IMAGE_DATA_DIRECTORY_SIZE;
    }
  } else {
    const uint8_t* number_of_rva_and_sizes_end =
        (uint8_t*) (&ctx->nt_header->optional._32bit.number_of_rva_and_sizes+1);
    if (number_of_rva_and_sizes_end > image_end) {
      image_optional_header_end = image_end + 1;
    } else {
      image_optional_header_end =
          (uint8_t*) &ctx->nt_header->optional._32bit.data_directory +
          ctx->nt_header->optional._32bit.number_of_rva_and_sizes*
          PE_IMAGE_DATA_DIRECTORY_SIZE;
    }
  }
  if (image_optional_header_end > image_end) {
    fprintf(stderr, "invalid image optional header: ends unexpectedly\n");
    return false;
  }

  /* ---- section table ---- */
  ctx->sections = (pe_image_section_header_t*) (
      ctx->image +
      ctx->dos_header->e_lfanew +
      sizeof(ctx->nt_header->signature) +
      PE_IMAGE_FILE_HEADER_SIZE +
      ctx->nt_header->file.size_of_optional_header);

  if ((uint8_t*) ctx->sections +
        ctx->nt_header->file.number_of_sections*PE_IMAGE_SECTION_HEADER_SIZE >
        image_end) {
    fprintf(stderr, "invalid section table: ends unexpectedly\n");
    return false;
  }
  return true;
}

bool readpe_context_initialize(readpe_context_t* ctx, const char* filename) {
  assert(ctx      != NULL);
  assert(filename != NULL);

  bool success = false;

  *ctx = (typeof(*ctx)) {0};

  FILE* fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "fopen failed: %s\n", filename);
    goto FINALIZE;
  }
  if (!readpe_context_copy_image_on_memory_(ctx, fp)) {
    goto FINALIZE;
  }
  if (!readpe_context_find_addresses_(ctx)) {
    goto FINALIZE;
  }

  success = true;
FINALIZE:
  if (fp != NULL) {
    fclose(fp);
  }
  if (!success) {
    readpe_context_deinitialize(ctx);
  }
  return success;
}

void readpe_context_deinitialize(readpe_context_t* ctx) {
  if (ctx == NULL) return;

  if (ctx->image != NULL) free(ctx->image);
}

