#include "./output.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

static const char* readpe_output_stringify_data_directory_entry_(size_t i) {
  switch (i) {
  case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
    return "export table";
  case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
    return "import table";
  case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
    return "resource table";
  case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
    return "exception table";
  case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
    return "certificate table";
  case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
    return "base relocation table";
  case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
    return "debug";
  case PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
    return "architecture data";
  case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
    return "global pointer";
  case PE_IMAGE_DIRECTORY_ENTRY_TLS:
    return "TLS table";
  case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
    return "load config table";
  case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
    return "bound import";
  case PE_IMAGE_DIRECTORY_ENTRY_IAT:
    return "import address table";
  case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
    return "delay import descriptor";
  case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
    return "CLR runtime header";
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

static void readpe_output_data_directories_(
    const pe_image_data_directory_t* dirs, size_t len) {
  assert(dirs != NULL || len == 0);

  printfln("data directories: %s", "");
  for (size_t i = 0; i < len; ++i) {
    printfln("  %02zu: %s",
        i, readpe_output_stringify_data_directory_entry_(i));

    printfln("    virtual address: 0x%08"PRIX32" RVA",
        dirs[i].virtual_address);
    printfln("    size           : 0x%08"PRIX32" = %"PRIu32,
        dirs[i].size, dirs[i].size);
  }
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
  printfln("image base                : 0x%08"PRIX32,
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

  printfln("number of RVA and sizes   : %"PRIu32,
      header->number_of_rva_and_sizes);

  readpe_output_data_directories_(
      header->data_directory, header->number_of_rva_and_sizes);

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
  printfln("image base                : 0x%016"PRIX64,
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

  printfln("number of RVA and sizes   : %"PRIu32,
      header->number_of_rva_and_sizes);

  readpe_output_data_directories_(
      header->data_directory, header->number_of_rva_and_sizes);

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

void readpe_output_nt_header(const pe_nt_header_t* header) {
  assert(header != NULL);

  readpe_output_begin_group_("NT HEADER");

  printfln("signature: %s (0x%04"PRIX16")",
      readpe_output_stringify_image_signature_(header->signature),
      header->signature);

  readpe_output_image_file_header_(&header->file);

  switch (header->file.machine) {
  case PE_IMAGE_FILE_MACHINE_I386:
    readpe_output_optional_header32_(&header->optional._32bit);
    break;
  case PE_IMAGE_FILE_MACHINE_AMD64:
  case PE_IMAGE_FILE_MACHINE_IA64:
    readpe_output_optional_header64_(&header->optional._64bit);
    break;
  }

  readpe_output_end_group_();
}

void readpe_output_section_table(
    const pe_image_section_header_t* table, size_t rows) {
  assert(table != NULL || rows == 0);

  readpe_output_begin_group_("section table");

  for (size_t i = 0; i < rows; ++i) {
    printfln("%zu:", i);
    printfln("  name                  : %.*s",
        PE_IMAGE_SECTION_NAME_SIZE, table[i].name);
    printfln("  virtual size          : 0x%08"PRIX32" = %"PRIu32,
        table[i].misc.virtual_size, table[i].misc.virtual_size);
    printfln("  virtual address       : 0x%08"PRIX32" RVA",
        table[i].virtual_address);
    printfln("  size of raw data      : 0x%08"PRIX32" = %"PRIu32,
        table[i].size_of_raw_data, table[i].size_of_raw_data);
    printfln("  pointer to raw data   : 0x%08"PRIX32,
        table[i].pointer_to_raw_data);
    printfln("  pointer to relocations: 0x%08"PRIX32,
        table[i].pointer_to_relocations);
    printfln("  pointer to linenumbers: 0x%08"PRIX32,
        table[i].pointer_to_linenumbers);
    printfln("  number of relocations : %"PRIu16,
        table[i].number_of_relocations);
    if (table[i].number_of_relocations == UINT16_MAX) {
      printfln("%s",
          "    check if PE_IMAGE_SECTION_LINK_NRELOC_OVERFLOW is "
          "set at characteristics property");
    }
    printfln("  number of linenumbers : %"PRIu16,
        table[i].number_of_linenumbers);

    printfln("  characteristics: 0x%08"PRIX32, table[i].characteristics);
#   define p(flag, desc) do {  \
      if ((table[i].characteristics & flag) == flag) {  \
        printfln("   - %s (0x%08"PRIX32")", #flag, flag);  \
        printfln("       %s", desc);  \
      }  \
    } while (0)

    p(PE_IMAGE_SECTION_CONTAINS_CODE,
        "the section contains executable code");
    p(PE_IMAGE_SECTION_CONTAINS_INITIALIZED_DATA,
        "the section contains initialized data");
    p(PE_IMAGE_SECTION_CONTAINS_UNINITIALIZED_DATA,
        "the section contains uninitialized data");
    p(PE_IMAGE_SECTION_LINK_INFO,
        "the section contains comments or other information "
        "(only for object file)");
    p(PE_IMAGE_SECTION_LINK_REMOVE,
        "the section will not become part of the image "
        "(only for object file)");
    p(PE_IMAGE_SECTION_LINK_COMDAT,
        "the section contains COMDAT data "
        "(only for object file)");
    p(PE_IMAGE_SECTION_NO_DEFER_SPEC_EXC,
        "reset speculative exceptions handling bits in "
        "the TLB entries for this section");
    p(PE_IMAGE_SECTION_GPREL,
        "the section contains data referenced through the global pointer");
    p(PE_IMAGE_SECTION_ALIGN_1BYTES,
        "align data on a 1-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_2BYTES,
        "align data on a 2-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_4BYTES,
        "align data on a 4-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_8BYTES,
        "align data on a 8-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_16BYTES,
        "align data on a 16-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_32BYTES,
        "align data on a 32-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_64BYTES,
        "align data on a 64-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_128BYTES,
        "align data on a 128-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_256BYTES,
        "align data on a 256-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_512BYTES,
        "align data on a 512-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_1024BYTES,
        "align data on a 1024-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_2048BYTES,
        "align data on a 2048-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_4096BYTES,
        "align data on a 4096-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_ALIGN_8192BYTES,
        "align data on a 8192-byte boundary "
        "(only for object file)");
    p(PE_IMAGE_SECTION_LINK_NRELOC_OVERFLOW,
        "the section contains extended relocations"
        "(number of relocations must be 0xfff)");
    p(PE_IMAGE_SECTION_MEMORY_DISCARDABLE,
        "the section can be discarded as needed");
    p(PE_IMAGE_SECTION_MEMORY_NOT_CACHED,
        "the section cannot be cached");
    p(PE_IMAGE_SECTION_MEMORY_NOT_PAGED,
        "the section cannot be paged");
    p(PE_IMAGE_SECTION_MEMORY_SHARED,
        "the section can be shared in memory");
    p(PE_IMAGE_SECTION_MEMORY_EXECUTE,
        "the section can be executed as code");
    p(PE_IMAGE_SECTION_MEMORY_READ,
        "the section can be read");
    p(PE_IMAGE_SECTION_MEMORY_WRITE,
        "the section can be written to");

#   undef p
  }

  readpe_output_end_group_();
}

void readpe_output_export_table(
    const uint8_t*                     img,
    const pe_image_export_directory_t* table,
    size_t                             section_length) {
  assert(img != NULL);

  readpe_output_begin_group_("export table");

  if (table == NULL) {
    printfln("%s", "no export table found");
    goto FINALIZE;
  }

  assert((uint8_t*) table >= img);
  assert(section_length >= PE_IMAGE_EXPORT_DIRECTORY_SIZE);

  const uint32_t* addrs = (uint32_t*) (img + table->address_of_functions);
  const uint32_t* names = (uint32_t*) (img + table->address_of_names);
  const uint16_t* ordis = (uint16_t*) (img + table->address_of_name_ordinals);

  const uintptr_t table_base = (uint8_t*) table - img;

  size_t longest = 0;
  for (size_t i = 0; i < table->number_of_names; ++i) {
    const size_t len = strlen((char*) &img[names[i]]);
    if (len > longest) longest = len;
  }

  for (size_t i = 0; i < table->number_of_functions; ++i) {
    const char* name    = "[anonymous function]";
    int32_t     ordinal = -1;

    for (size_t j = 0; j < table->number_of_names; ++j) {
      if (ordis[j] == i) {
        name    = (char*) &img[names[j]];
        ordinal = ordis[j] + table->base;
        break;
      }
    }

    if (table_base <= addrs[i] && addrs[i] < table_base + section_length) {
      printfln(
          "%-*s@%-10"PRId32" 0x%08"PRIX32" (forwarded to '%s')",
          (int) longest,
          name,
          ordinal,
          addrs[i],
          (char*) &img[addrs[i]]);
    } else {
      printfln(
          "%-*s@%-10"PRId32" 0x%08"PRIX32,
          (int) longest,
          name,
          ordinal,
          addrs[i]);
    }
  }

FINALIZE:
  readpe_output_end_group_();
}

void readpe_output_import_table(
    const uint8_t*                      img,
    const pe_image_import_descriptor_t* table,
    bool                                _64bit) {
  assert(img != NULL);

  readpe_output_begin_group_("import table");

  if (table == NULL) {
    printfln("%s", "no import table found");
    goto FINALIZE;
  }

  const pe_image_import_descriptor_t* itr = table;
  for (size_t i = 0; itr->characteristics != 0; ++i, ++itr) {
    printfln("%zu:", i);
    printfln("  name                : %s",
        &img[itr->name]);
    printfln("  original first thunk: 0x%08"PRIX32,
        itr->original_first_thunk);
    printfln("  first thunk         : 0x%08"PRIX32,
        itr->first_thunk);
    printfln("  forwarder chain     : 0x%08"PRIX32,
        itr->forwarder_chain);

    if (itr->time_date_stamp == 0) {
      printfln("  time date stamp     : %d", 0);
    } else {
      printfln("  time date stamp     : %s",
          readpe_output_stringify_time_(itr->time_date_stamp));
    }

    printfln("%s", "  INT                 :");

    const uint8_t* int_itr = img + itr->original_first_thunk;
    for (;;) {
      uintmax_t value   = 0;
      bool      ordinal = false;

      if (_64bit) {
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

      if (ordinal) {
        printfln("    @%7"PRIuMAX": [anonymous function]", value);
      } else {
        const pe_image_import_by_name_t* ibn = (typeof(ibn)) (img + value);
        printfln("    %8"PRIu32": %s", ibn->hint, ibn->name);
      }
    }
  }

FINALIZE:
  readpe_output_end_group_();
}

void readpe_output_relocation_table(const uint8_t* table, size_t length) {
  readpe_output_begin_group_("relocation table");

  if (table == NULL) {
    printfln("%s", "no relocation table found");
    goto FINALIZE;
  }

  size_t relocs = 0;

  const uint8_t* itr = table;
  const uint8_t* end = itr + length;
  for (size_t cnt = 0; itr < end; ++cnt) {
    const pe_base_relocation_block_t* block = (typeof(block)) itr;
    itr += PE_BASE_RELOCATION_BLOCK_SIZE;

    printfln("block %zu:", cnt);
    printfln("  virtual address: 0x%08"PRIX32,
        block->virtual_address);
    printfln("  block size     : 0x%08"PRIX32" = %"PRIu32,
        block->size_of_block, block->size_of_block);

    const size_t cnt = (block->size_of_block - PE_BASE_RELOCATION_BLOCK_SIZE) /
        PE_BASE_RELOCATION_ENTRY_SIZE;
    printfln("  entries        : %zu found", cnt);

    for (size_t i = 0; i < cnt; ++i) {
      const pe_base_relocation_entry_t* entry = (typeof(entry)) itr;
      itr += PE_BASE_RELOCATION_ENTRY_SIZE;

      printfln("    0x%08"PRIX32": type=%2"PRIu8,
          entry->offset + block->virtual_address,
          entry->type);
    }
    relocs += cnt;
  }
  printfln("total %zu addresses to be relocated found", relocs);

FINALIZE:
  readpe_output_end_group_();
}
