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

static const char* readpe_output_stringify_optional_magic_(uint16_t magic) {
  switch (magic) {
  case PE_IMAGE_OPTIONAL_HEADER_MAGIC_NT_HDR32:
    return "32-bit executable";
  case PE_IMAGE_OPTIONAL_HEADER_MAGIC_NT_HDR64:
    return "64-bit executable";
  case PE_IMAGE_OPTIONAL_HEADER_MAGIC_ROM_HDR64:
    return "rom";
  default:
    return "unknown";
  }
}

static const char* readpe_output_stringify_optional_subsystem_(uint16_t subsys) {
  switch (subsys) {
  case PE_IMAGE_SUBSYSTEM_NATIVE:
    return "native";
  case PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
    return "Windows GUI";
  case PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
    return "Windows CUI";
  case PE_IMAGE_SUBSYSTEM_OS2_CUI:
    return "OS2 CUI";
  case PE_IMAGE_SUBSYSTEM_POSIX_CUI:
    return "POSIX CUI";
  case PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
    return "Windows CE GUI";
  case PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
    return "EFI application";
  case PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    return "EFI boot service driver";
  case PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    return "EFI runtime driver";
  case PE_IMAGE_SUBSYSTEM_EFI_ROM:
    return "EFI ROM";
  case PE_IMAGE_SUBSYSTEM_XBOX:
    return "Xbox";
  case PE_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
    return "Windows boot application";
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
  printfln("number of sections     : %"PRIu16, header->number_of_sections);
  printfln("time date stamp        : %s",
      readpe_output_stringify_time_(header->time_date_stamp));
  printfln("pointer to symbol table: 0x%08"PRIX32,
      header->pointer_to_symbol_table);
  printfln("number of symbols      : %"PRIu32, header->number_of_symbols);
  printfln("size of optional header: 0x%04"PRIX16,
      header->size_of_optional_header);

  printfln("characteristics        : 0x%04"PRIX16, header->characteristics);

# define p(flag, desc) do {  \
    if (header->characteristics & flag) {  \
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

static void readpe_output_optional_header32_(
    const pe32_image_optional_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("OPTIONAL HEADER 32-bit");

  printfln("magic                     : %s (0x%04"PRIX16")",
      readpe_output_stringify_optional_magic_(header->magic), header->magic);
  printfln("linker version            : %"PRIu8".%"PRIu8,
      header->major_linker_version, header->minor_linker_version);
  printfln("size of code              : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_code, header->size_of_code);
  printfln("size of initialized data  : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_initialized_data, header->size_of_initialized_data);
  printfln("size of uninitialized data: 0x%08"PRIX32" = %"PRIu32,
      header->size_of_uninitialized_data, header->size_of_uninitialized_data);
  printfln("address of entrypoint     : 0x%08"PRIX32" RVA",
      header->address_of_entrypoint);
  printfln("base of code              : 0x%08"PRIX32" RVA",
      header->base_of_code);
  printfln("base of data              : 0x%08"PRIX32" RVA",
      header->base_of_data);
  printfln("image base                : 0x%08"PRIX32" RVA",
      header->image_base);
  printfln("section alignment         : 0x%08"PRIX32" = %"PRIu32,
      header->section_alignment, header->section_alignment);
  printfln("file alignment            : 0x%08"PRIX32" = %"PRIu32,
      header->file_alignment, header->file_alignment);
  printfln("OS version                : %"PRIu16".%"PRIu16,
      header->major_operating_system_version,
      header->minor_operating_system_version);
  printfln("image version             : %"PRIu16".%"PRIu16,
      header->major_image_version, header->minor_image_version);
  printfln("subsystem version         : %"PRIu16".%"PRIu16,
      header->major_subsystem_version, header->minor_subsystem_version);
  printfln("size of image             : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_image, header->size_of_image);
  printfln("size of headers           : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_headers, header->size_of_headers);
  printfln("checksum                  : 0x%08"PRIX32" = %"PRIu32,
      header->checksum, header->checksum);
  printfln("subsystem                 : %s (0x%04"PRIX16")",
      readpe_output_stringify_optional_subsystem_(header->subsystem),
      header->subsystem);

  printfln("dll characteristics       : 0x%04"PRIX16,
      header->dll_characteristics);

# define p(flag, desc) do {  \
    if (header->dll_characteristics & flag) {  \
      printfln("  - %s (0x%04"PRIX16")", #flag, flag);  \
      printfln("      %s", desc);  \
    }  \
  } while (0)

  p(PE_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
      "the dll can be relocated at load time");
  p(PE_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
      "integrity checks are forced");
  p(PE_IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
      "the image is compatible with data execution prevention");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
      "the image is isolation aware");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_SEH,
      "the image does not use structured exception handling");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_BIND,
      "don't bind the image");
  p(PE_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
      "A WDM driver");
  p(PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
      "the image is terminal server aware");

# undef p

  printfln("size of stack reserve     : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_stack_reserve, header->size_of_stack_reserve);
  printfln("size of stack commit      : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_stack_commit, header->size_of_stack_commit);
  printfln("size of heap reserve      : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_heap_reserve, header->size_of_heap_reserve);
  printfln("size of heap commit       : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_heap_commit, header->size_of_heap_commit);

  printfln("number of RVA and sizes   : %"PRId32,
      header->number_of_rva_and_sizes);

  /* TODO(catfoot): print data directory */

  readpe_output_end_group_();
}

static void readpe_output_optional_header64_(
    const pe64_image_optional_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("OPTIONAL HEADER 64-bit");

  printfln("magic                     : %s (0x%04"PRIX16")",
      readpe_output_stringify_optional_magic_(header->magic), header->magic);
  printfln("linker version            : %"PRIu8".%"PRIu8,
      header->major_linker_version, header->minor_linker_version);
  printfln("size of code              : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_code, header->size_of_code);
  printfln("size of initialized data  : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_initialized_data, header->size_of_initialized_data);
  printfln("size of uninitialized data: 0x%08"PRIX32" = %"PRIu32,
      header->size_of_uninitialized_data, header->size_of_uninitialized_data);
  printfln("address of entrypoint     : 0x%08"PRIX32" RVA",
      header->address_of_entrypoint);
  printfln("base of code              : 0x%08"PRIX32" RVA",
      header->base_of_code);
  printfln("image base                : 0x%016"PRIX64" RVA",
      header->image_base);
  printfln("section alignment         : 0x%08"PRIX32" = %"PRIu32,
      header->section_alignment, header->section_alignment);
  printfln("file alignment            : 0x%08"PRIX32" = %"PRIu32,
      header->file_alignment, header->file_alignment);
  printfln("OS version                : %"PRIu16".%"PRIu16,
      header->major_operating_system_version,
      header->minor_operating_system_version);
  printfln("image version             : %"PRIu16".%"PRIu16,
      header->major_image_version, header->minor_image_version);
  printfln("subsystem version         : %"PRIu16".%"PRIu16,
      header->major_subsystem_version, header->minor_subsystem_version);
  printfln("size of image             : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_image, header->size_of_image);
  printfln("size of headers           : 0x%08"PRIX32" = %"PRIu32,
      header->size_of_headers, header->size_of_headers);
  printfln("checksum                  : 0x%08"PRIX32" = %"PRIu32,
      header->checksum, header->checksum);
  printfln("subsystem                 : %s (0x%04"PRIX16")",
      readpe_output_stringify_optional_subsystem_(header->subsystem),
      header->subsystem);

  printfln("dll characteristics       : 0x%04"PRIX16,
      header->dll_characteristics);

# define p(flag, desc) do {  \
    if (header->dll_characteristics & flag) {  \
      printfln("  - %s (0x%04"PRIX16")", #flag, flag);  \
      printfln("      %s", desc);  \
    }  \
  } while (0)

  p(PE_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
      "the dll can be relocated at load time");
  p(PE_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
      "integrity checks are forced");
  p(PE_IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
      "the image is compatible with data execution prevention");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
      "the image is isolation aware");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_SEH,
      "the image does not use structured exception handling");
  p(PE_IMAGE_DLLCHARACTERISTICS_NO_BIND,
      "don't bind the image");
  p(PE_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
      "A WDM driver");
  p(PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
      "the image is terminal server aware");

# undef p

  printfln("size of stack reserve     : 0x%016"PRIX64" = %"PRIu64,
      header->size_of_stack_reserve, header->size_of_stack_reserve);
  printfln("size of stack commit      : 0x%016"PRIX64" = %"PRIu64,
      header->size_of_stack_commit, header->size_of_stack_commit);
  printfln("size of heap reserve      : 0x%016"PRIX64" = %"PRIu64,
      header->size_of_heap_reserve, header->size_of_heap_reserve);
  printfln("size of heap commit       : 0x%016"PRIX64" = %"PRIu64,
      header->size_of_heap_commit, header->size_of_heap_commit);

  printfln("number of RVA and sizes   : %"PRId32,
      header->number_of_rva_and_sizes);

  /* TODO(catfoot): print data directory */

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

  readpe_output_optional_header32_(&header->optional);

  readpe_output_end_group_();
}

void readpe_output_nt_header64(const pe64_nt_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("NT HEADER (64 bit)");

  printfln("signature: %s (0x%04"PRIX16")",
      readpe_output_stringify_image_signature_(header->signature),
      header->signature & 0xFFFF);

  readpe_output_image_file_header_(&header->file);

  readpe_output_optional_header64_(&header->optional);

  readpe_output_end_group_();
}
