#include "./context.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"

static bool readpe_context_validate_string_(
    const readpe_context_t* ctx, size_t rva) {
  assert(ctx != NULL);

  if (rva >= ctx->image_length) {
    return false;
  }

  const size_t mlen = ctx->image_length - rva;
  const size_t len = strnlen((char*) (ctx->image+rva), mlen);
  if (len == mlen && ctx->image[ctx->image_length-1] != 0) {
    return false;
  }
  return true;
}

static bool readpe_context_copy_headers_on_memory_(
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
  if (dos_header.e_lfanew < 0) {
    fprintf(stderr,
        "offset of nt header is negative (%"PRId32")\n", dos_header.e_lfanew);
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
    ctx->image_length  = nt_header.optional._32bit.size_of_image;
    ctx->header_length = nt_header.optional._32bit.size_of_headers;
    break;
  case PE_IMAGE_FILE_MACHINE_AMD64:
  case PE_IMAGE_FILE_MACHINE_IA64:
    ctx->_64bit = true;
    ctx->image_length  = nt_header.optional._64bit.size_of_image;
    ctx->header_length = nt_header.optional._64bit.size_of_headers;
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
  if (ctx->header_length == 0) {
    fprintf(stderr, "invalid image optional header: size_of_headers is 0\n");
    return false;
  }
  if (ctx->header_length > ctx->image_length) {
    fprintf(stderr,
        "invalid image optional header: "
        "size_of_headers is larger than size_of_image\n");
    return false;
  }

  ctx->image = calloc(ctx->image_length, 1);
  if (ctx->image == NULL) {
    fprintf(stderr,
        "failed to allocate memory for image (%zu bytes)\n", ctx->image_length);
  }

  fseek(fp, 0, SEEK_SET);
  if (fread(ctx->image, ctx->header_length, 1, fp) != 1) {
    fprintf(stderr, "fread failed while reading headers\n");
    return false;
  }
  return true;
}

static bool readpe_context_find_addresses_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  const uint8_t* header_end = ctx->image + ctx->header_length;
  assert(header_end <= ctx->image + ctx->image_length);

  /* ---- dos header ---- */
  ctx->dos_header = (pe_dos_header_t*) ctx->image;

  if (ctx->header_length < PE_DOS_HEADER_SIZE) {
    fprintf(stderr, "invalid dos header: ends unexpectedly");
    return false;
  }

  /* ---- dos stub ---- */
  ctx->dos_stub        = ctx->image + PE_DOS_HEADER_SIZE;
  ctx->dos_stub_length = ctx->dos_header->e_lfanew - PE_DOS_HEADER_SIZE;

  if (ctx->dos_header->e_lfanew < PE_DOS_HEADER_SIZE ||
      (size_t) ctx->dos_header->e_lfanew > ctx->header_length) {
    fprintf(stderr, "invalid dos stub: ends unexpectedly\n");
    return false;
  }

  /* ---- nt header ---- */
  ctx->nt_header = (pe_nt_header_t*) (ctx->image + ctx->dos_header->e_lfanew);

  if ((uint8_t*) &ctx->nt_header->file > header_end) {
    fprintf(stderr, "invalid image signature: ends unexpectedly\n");
    return false;
  }
  if ((uint8_t*) &ctx->nt_header->optional > header_end) {
    fprintf(stderr, "invalid image file header: ends unexpectedly\n");
    return false;
  }

  /* ---- data directory ---- */
  if (ctx->_64bit) {
    ctx->data_directory_length =
        ctx->nt_header->optional._64bit.number_of_rva_and_sizes;
    ctx->data_directory = ctx->nt_header->optional._64bit.data_directory;
  } else {
    ctx->data_directory_length =
        ctx->nt_header->optional._32bit.number_of_rva_and_sizes;
    ctx->data_directory = ctx->nt_header->optional._32bit.data_directory;
  }
  if ((uint8_t*) ctx->data_directory +
        ctx->data_directory_length*PE_IMAGE_DATA_DIRECTORY_SIZE > header_end) {
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
        header_end) {
    fprintf(stderr, "invalid section table: ends unexpectedly\n");
    return false;
  }
  return true;
}

static bool readpe_context_copy_sections_on_memory_(
    readpe_context_t* ctx, FILE* fp) {
  assert(ctx != NULL);
  assert(fp  != NULL);

  for (size_t i = 0; i < ctx->nt_header->file.number_of_sections; ++i) {
    const pe_image_section_header_t* s = &ctx->sections[i];
    if (s->size_of_raw_data == 0) continue;

    uint8_t* ptr = ctx->image + s->virtual_address;
    if (ptr + s->misc.virtual_size >= ctx->image + ctx->image_length) {
      fprintf(stderr, "invalid section '%.*s': larger than image size\n",
          PE_IMAGE_SECTION_NAME_SIZE, s->name);
      return false;
    }

    fseek(fp, s->pointer_to_raw_data, SEEK_SET);
    if (fread(ptr, s->size_of_raw_data, 1, fp) != 1) {
      fprintf(stderr,
          "fread failed while reading section: '%.*s'\n",
          PE_IMAGE_SECTION_NAME_SIZE, s->name);
      return false;
    }
  }

  return true;
}

static bool readpe_context_find_export_table_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  ctx->exports                = NULL;
  ctx->exports_section_length = 0;

  if (ctx->data_directory_length <= PE_IMAGE_DIRECTORY_ENTRY_EXPORT) {
    return true;
  }

  const pe_image_data_directory_t* dir =
      &ctx->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dir->virtual_address == 0 || dir->size == 0) return true;

  ctx->exports = (typeof(ctx->exports)) (ctx->image + dir->virtual_address);
  ctx->exports_section_length = dir->size;

  if ((uint8_t*) ctx->exports + PE_IMAGE_EXPORT_DIRECTORY_SIZE >=
        ctx->image + ctx->image_length) {
    fprintf(stderr, "invalid export table: ends unexpectedly\n");
    return false;
  }

  if (!readpe_context_validate_string_(ctx, ctx->exports->name)) {
    fprintf(stderr, "invalid export table: name refers out of image\n");
    return false;
  }

  if (ctx->exports->address_of_functions +
        ctx->exports->number_of_functions*sizeof(uint32_t) >=
        ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_functions refers out of image\n");
    return false;
  }
  if (ctx->exports->address_of_names +
        ctx->exports->number_of_names*sizeof(uint32_t) >= ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_names refers out of image\n");
    return false;
  }
  if (ctx->exports->address_of_name_ordinals +
        ctx->exports->number_of_names*sizeof(uint16_t) >= ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_name_ordinals refers out of image\n");
    return false;
  }

  const uint32_t* funcs =
      (uint32_t*) (ctx->image + ctx->exports->address_of_functions);
  for (size_t i = 0; i < ctx->exports->number_of_functions; ++i) {
    if (funcs[i] >= ctx->image_length) {
      fprintf(stderr,
          "invalid export table: one of the functions is out of image\n");
      return false;
    }
    if (dir->virtual_address <=
          funcs[i] && funcs[i] < dir->virtual_address + dir->size &&
        !readpe_context_validate_string_(ctx, funcs[i])) {
      fprintf(stderr,
          "invalid export table: "
          "one of the forwarded function names ends unexpectedly\n");
      return false;
    }
  }

  const uint32_t* names =
      (uint32_t*) (ctx->image + ctx->exports->address_of_names);
  for (size_t i = 0; i < ctx->exports->number_of_names; ++i) {
    if (!readpe_context_validate_string_(ctx, names[i])) {
      fprintf(stderr,
          "invalid export table: one of the names ends unexpectedly\n");
      return false;
    }
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
  if (!readpe_context_copy_headers_on_memory_(ctx, fp)) {
    goto FINALIZE;
  }
  if (!readpe_context_find_addresses_(ctx)) {
    goto FINALIZE;
  }
  if (!readpe_context_copy_sections_on_memory_(ctx, fp)) {
    goto FINALIZE;
  }
  if (!readpe_context_find_export_table_(ctx)) {
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
