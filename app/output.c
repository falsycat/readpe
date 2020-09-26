#include "./output.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#include "pe.h"

static size_t output_indent_ = 0;

#define printfln(fmt, ...) do {  \
  readpe_output_indent_();  \
  printf(fmt"\n", __VA_ARGS__);  \
} while (0)

static inline void readpe_output_indent_(void) {
  if (output_indent_ > 0) {
    printf("%*c", (int) output_indent_*2, ' ');
  }
}
static inline void readpe_output_begin_group_(const char* name) {
  printf("\n");
  printfln("---- %s", name);
  ++output_indent_;
}
static inline void readpe_output_end_group_(void) {
  assert(output_indent_ > 0);

  --output_indent_;
}

static void readpe_output_binary_(const uint8_t* body, size_t len) {
  assert(body != NULL || len == 0);

  const uint8_t* itr = body;
  const uint8_t* end = body + len;

  for (size_t i = 0; itr < end; ++i) {
    readpe_output_indent_();
    printf("%06"PRIX64":", (uint64_t) i*16);

    char str[16] = {0};
    for (size_t j = 0; j < 16 && itr < end; ++j) {
      if (j%2 == 0) printf(" ");
      str[j] = *(itr++);
      printf("%02"PRIX8, (uint8_t) str[j]);
      if (!isprint(str[j])) str[j] = '.';
    }
    printf("    %.16s\n", str);
  }
}

static const char* readpe_output_stringify_time_(uint32_t ts) {
  static char result[64];

  const time_t t = (time_t) ts;
  strftime(result, sizeof(result), "%Y/%m/%d %A %H:%M:%S", localtime(&t));
  return result;
}

static const char* readpe_output_stringify_image_signature_(
    uint32_t signature) {

  if (signature == PE_IMAGE_SIGNATURE_NT) {
    return "PE";
  }
  switch (signature & 0xFFFF) {
  case PE_IMAGE_SIGNATURE_DOS:
    return "DOS";
  case PE_IMAGE_SIGNATURE_OS2:
    return "OS2";
  case PE_IMAGE_SIGNATURE_OS2_LE:
    return "OS2 LE";
  default:
    return "unknown";
  }
}

static const char* readpe_output_stringify_machine_(uint16_t machine) {
  switch (machine) {
  case PE_IMAGE_FILE_MACHINE_I386:
    return "x86";
  case PE_IMAGE_FILE_MACHINE_IA64:
    return "Intel Itanium";
  case PE_IMAGE_FILE_MACHINE_AMD64:
    return "x64";
  default:
    return "unknown";
  }
}

static void readpe_output_image_file_header_(
    const pe_image_file_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("IMAGE FILE HEADER");

  printfln("machine                : %s (0x%04"PRIX16")",
      readpe_output_stringify_machine_(header->machine), header->machine);
  printfln("number of sections     : %"PRId16, header->number_of_sections);
  printfln("time date stamp        : %s",
      readpe_output_stringify_time_(header->time_date_stamp));
  printfln("pointer to symbol table: 0x%08"PRIX32,
      header->pointer_to_symbol_table);
  printfln("number of symbols      : %"PRId32, header->number_of_symbols);
  printfln("size of optional header: 0x%04"PRIX16,
      header->size_of_optional_header);

  const uint16_t ch = header->characteristics;
  printfln("characteristics        : 0x%04"PRIX16, ch);

# define p(flag, desc) do {  \
    if (ch & flag) {  \
      printfln("  - %s (0x%04"PRIX16")", #flag, flag);  \
      printfln("      %s", desc);  \
    }  \
  } while (0)

  /* doesn't check obsolete flags */

  p(PE_IMAGE_FILE_RELOCS_STRIPPED,
      "relocation info was stripped");
  p(PE_IMAGE_FILE_EXECUTABLE_IMAGE,
      "the image is executable (no unresolved reference)");
  p(PE_IMAGE_FILE_LINE_NUMS_STRIPPED,
      "COFF line numbers were stripped");
  p(PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED,
      "COFF symbol table entries were stripped");
  p(PE_IMAGE_FILE_LARGE_ADDRESS_AWARE,
      "the image can handle addresses larger than 2GB");
  p(PE_IMAGE_FILE_32BIT_MACHINE,
      "computer supports 32-bit words");
  p(PE_IMAGE_FILE_DEBUG_STRIPPED,
      "debugging info was stripped");
  p(PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
      "if the image is on removable media, run it from swap file");
  p(PE_IMAGE_FILE_NET_RUN_FROM_SWAP,
      "if the image is on the network, run it from swap file");
  p(PE_IMAGE_FILE_SYSTEM,
      "the image is a system file");
  p(PE_IMAGE_FILE_DLL,
      "the image is a DLL file (cannot run directly)");
  p(PE_IMAGE_FILE_UP_SYSTEM_ONLY,
      "the image should be run only on a uniprocessor computer");

# undef p

  readpe_output_end_group_();
}

void readpe_output_dos_header(const pe_dos_header_t* dos_header) {
  assert(dos_header != NULL);

  readpe_output_begin_group_("DOS HEADER");

  printfln("e_magic : 0x%04"PRIX16, dos_header->e_magic);
  printfln("e_lfanew: 0x%08"PRIX32, dos_header->e_lfanew);

  readpe_output_end_group_();
}

void readpe_output_dos_stub(const uint8_t* body, size_t len) {
  assert(body != NULL || len == 0);

  readpe_output_begin_group_("DOS STUB");

  readpe_output_binary_(body, len);

  readpe_output_end_group_();
}

void readpe_output_nt_header32(const pe32_nt_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("NT HEADER (32 bit)");

  printfln("signature: %s (0x%04"PRIX16")",
      readpe_output_stringify_image_signature_(header->signature),
      header->signature);

  readpe_output_image_file_header_(&header->file);

  /* TODO(catfoot): */

  readpe_output_end_group_();
}

void readpe_output_nt_header64(const pe64_nt_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("NT HEADER (64 bit)");

  printfln("signature: %s (0x%04"PRIX16")",
      readpe_output_stringify_image_signature_(header->signature),
      header->signature & 0xFFFF);

  readpe_output_image_file_header_(&header->file);

  /* TODO(catfoot): */

  readpe_output_end_group_();
}
