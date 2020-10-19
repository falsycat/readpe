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
    const readpe_context_t* ctx, uintmax_t rva) {
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
    ctx->image_base    = nt_header.optional._32bit.image_base;
    ctx->image_length  = nt_header.optional._32bit.size_of_image;
    ctx->header_length = nt_header.optional._32bit.size_of_headers;
    break;
  case PE_IMAGE_FILE_MACHINE_AMD64:
  case PE_IMAGE_FILE_MACHINE_IA64:
    ctx->_64bit = true;
    ctx->image_base    = nt_header.optional._64bit.image_base;
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
      fprintf(stderr,
          "invalid section '%.*s' (index=%zu): larger than image size\n",
          PE_IMAGE_SECTION_NAME_SIZE, s->name, i);
      return false;
    }

    fseek(fp, s->pointer_to_raw_data, SEEK_SET);
    if (fread(ptr, s->size_of_raw_data, 1, fp) != 1) {
      fprintf(stderr,
          "fread failed while reading section: '%.*s' (index=%zu)\n",
          PE_IMAGE_SECTION_NAME_SIZE, s->name, i);
      return false;
    }
  }

  return true;
}

static bool readpe_context_find_export_table_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  if (ctx->data_directory_length <= PE_IMAGE_DIRECTORY_ENTRY_EXPORT) {
    return true;
  }

  const pe_image_data_directory_t* dir =
      &ctx->data_directory[PE_IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dir->virtual_address == 0 || dir->size == 0) return true;

  ctx->export_ = (typeof(ctx->export_)) (ctx->image + dir->virtual_address);
  ctx->export_section_length = dir->size;

  if ((uint8_t*) ctx->export_ + dir->size > ctx->image + ctx->image_length ||
      dir->size < PE_IMAGE_EXPORT_DIRECTORY_SIZE) {
    fprintf(stderr, "invalid export table: ends unexpectedly\n");
    return false;
  }

  if (!readpe_context_validate_string_(ctx, ctx->export_->name)) {
    fprintf(stderr, "invalid export table: name refers out of image\n");
    return false;
  }

  if (ctx->export_->address_of_functions +
        ctx->export_->number_of_functions*sizeof(uint32_t) >
        ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_functions refers out of image\n");
    return false;
  }
  if (ctx->export_->address_of_names +
        ctx->export_->number_of_names*sizeof(uint32_t) > ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_names refers out of image\n");
    return false;
  }
  if (ctx->export_->address_of_name_ordinals +
        ctx->export_->number_of_names*sizeof(uint16_t) > ctx->image_length) {
    fprintf(stderr,
        "invalid export table: "
        "address_of_name_ordinals refers out of image\n");
    return false;
  }

  const uint32_t* funcs =
      (uint32_t*) (ctx->image + ctx->export_->address_of_functions);
  for (size_t i = 0; i < ctx->export_->number_of_functions; ++i) {
    if (funcs[i] >= ctx->image_length) {
      fprintf(stderr,
          "invalid export table: the function (index=%zu) is out of image\n",
          i);
      return false;
    }
  }

  const uint32_t* names =
      (uint32_t*) (ctx->image + ctx->export_->address_of_names);
  for (size_t i = 0; i < ctx->export_->number_of_names; ++i) {
    if (!readpe_context_validate_string_(ctx, names[i])) {
      fprintf(stderr,
          "invalid export table: the name (index=%zu) ends unexpectedly\n", i);
      return false;
    }
  }
  return true;
}

static bool readpe_context_find_import_table_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  if (ctx->data_directory_length <= PE_IMAGE_DIRECTORY_ENTRY_IMPORT) {
    return true;
  }

  const pe_image_data_directory_t* dir =
      &ctx->data_directory[PE_IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (dir->virtual_address == 0 || dir->size == 0) return true;

  ctx->imports = (typeof(ctx->imports)) (ctx->image + dir->virtual_address);

  const uint8_t* img_end = ctx->image + ctx->image_length;

  const pe_image_import_descriptor_t* end = ctx->imports;
  while (end->characteristics != 0) {
    static const size_t minsz =
        offsetof(pe_image_import_descriptor_t, characteristics) +
        sizeof(end->characteristics);

    ++end;
    if ((uint8_t*) end + minsz > img_end) {
      fprintf(stderr, "invalid import table: ends unexpectedly\n");
      return false;
    }
  }
  ctx->imports_length = end - ctx->imports;

  const pe_image_import_descriptor_t* itr = ctx->imports;
  for (size_t i = 0; itr < end; ++i, ++itr) {
    if (itr->original_first_thunk >= ctx->image_length) {
      fprintf(stderr,
          "invalid import descriptor (index=%zu): "
          "original_first_thunk refers out of image\n", i);
      return false;
    }
    if (!readpe_context_validate_string_(ctx, itr->name)) {
      fprintf(stderr,
          "invalid import descriptor (index=%zu): "
          "the name ends unexpectedly\n", i);
      return false;
    }
    if (itr->first_thunk >= ctx->image_length) {
      fprintf(stderr,
          "invalid import descriptor (index=%zu): "
          "first_thunk refers out of image\n", i);
      return false;
    }

    const uint8_t* int_itr = ctx->image + itr->original_first_thunk;
    size_t int_len;
    for (int_len = 0; int_itr < img_end; ++int_len) {
      uintmax_t value   = 0;
      bool      ordinal = false;

      if (ctx->_64bit) {
        value = ((pe64_image_thunk_data_t*) int_itr)->address_of_data;
        int_itr += PE64_IMAGE_THUNK_DATA_SIZE;
        if (value == 0) break;

        ordinal = value & PE64_IMAGE_ORDINAL_FLAG;
        if (ordinal) value &= PE64_IMAGE_ORDINAL;

      } else {
        value = ((pe32_image_thunk_data_t*) int_itr)->address_of_data;
        int_itr += PE32_IMAGE_THUNK_DATA_SIZE;
        if (value == 0) break;

        ordinal = value & PE32_IMAGE_ORDINAL_FLAG;
        if (ordinal) value &= PE32_IMAGE_ORDINAL;
      }
      if (!ordinal && !readpe_context_validate_string_(
            ctx, value + offsetof(pe_image_import_by_name_t, name))) {
        fprintf(stderr,
            "invalid import descriptor (index=%zu): "
            "the name (index=%zu) ends unexpectedly\n", i, int_len);
        return false;
      }
    }

    const uint8_t* iat_itr = ctx->image + itr->first_thunk;
    for (size_t j = 0; j < int_len; ++j) {
      uintmax_t value = 0;
      if (ctx->_64bit) {
        value = ((pe64_image_thunk_data_t*) iat_itr)->address_of_data;
        iat_itr += PE64_IMAGE_THUNK_DATA_SIZE;
      } else {
        value = ((pe32_image_thunk_data_t*) iat_itr)->address_of_data;
        iat_itr += PE32_IMAGE_THUNK_DATA_SIZE;
      }
      if (value == 0) {
        fprintf(stderr,
            "invalid import descriptor (index=%zu): "
            "IAT ends unexpectedly\n", i);
        return false;
      }
    }
  }
  return true;
}

static bool readpe_context_find_relocation_table_(readpe_context_t* ctx) {
  assert(ctx != NULL);

  if (ctx->data_directory_length <= PE_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
    return true;
  }

  const pe_image_data_directory_t* dir =
      &ctx->data_directory[PE_IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (dir->virtual_address == 0 || dir->size == 0) return true;

  ctx->relocations        = ctx->image + dir->virtual_address;
  ctx->relocations_length = dir->size;

  const uint8_t* itr = ctx->relocations;
  const uint8_t* end = itr + ctx->relocations_length;
  for (size_t i = 0; itr < end; ++i) {
    const pe_base_relocation_block_t* block = (typeof(block)) itr;
    itr += PE_BASE_RELOCATION_BLOCK_SIZE;

    if (block->size_of_block < PE_BASE_RELOCATION_BLOCK_SIZE) {
      fprintf(stderr,
          "invalid relocation table: "
          "the block (index=%zu) ends unexpectedly\n", i);
      return false;
    }

    const size_t cnt = (block->size_of_block - PE_BASE_RELOCATION_BLOCK_SIZE) /
        PE_BASE_RELOCATION_ENTRY_SIZE;
    for (size_t j = 0; j < cnt; ++j) {
      const pe_base_relocation_entry_t* entry = (typeof(entry)) itr;
      itr += PE_BASE_RELOCATION_ENTRY_SIZE;

      if (entry->type == 0) continue;
      if (block->virtual_address + entry->offset + sizeof(uint32_t) >
            ctx->image_length) {
        fprintf(stderr,
            "invalid relocation table block (index=%zu): "
            "the address (index=%zu) refers out of image\n", i, j);
        return false;
      }
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
  if (!readpe_context_copy_headers_on_memory_(ctx, fp)  ||
      !readpe_context_find_addresses_(ctx)              ||
      !readpe_context_copy_sections_on_memory_(ctx, fp) ||
      !readpe_context_find_export_table_(ctx)           ||
      !readpe_context_find_import_table_(ctx)           ||
      !readpe_context_find_relocation_table_(ctx)) {
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
