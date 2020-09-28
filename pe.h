#pragma once

#include <stdint.h>

typedef struct pe_dos_header_t {
# define PE_DOS_HEADER_SIZE 64

  uint16_t e_magic;
# define PE_DOS_MAGIC 0x5A4D

  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t eminalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t eip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  int32_t  e_lfanew;
} pe_dos_header_t;

typedef struct pe_image_file_header_t {
# define PE_IMAGE_FILE_HEADER_SIZE 20

  uint16_t machine;
# define PE_IMAGE_FILE_MACHINE_I386  0x014C
# define PE_IMAGE_FILE_MACHINE_IA64  0x0200
# define PE_IMAGE_FILE_MACHINE_AMD64 0x8664

  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;

  uint16_t characteristics;
# define PE_IMAGE_FILE_RELOCS_STRIPPED         0x0001
# define PE_IMAGE_FILE_EXECUTABLE_IMAGE        0x0002
# define PE_IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004
# define PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
# define PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
# define PE_IMAGE_FILE_AGGRESIVE_WS_TRIM       0x0010
# define PE_IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020
# define PE_IMAGE_FILE_BYTES_REVERSED_LO       0x0080
# define PE_IMAGE_FILE_32BIT_MACHINE           0x0100
# define PE_IMAGE_FILE_DEBUG_STRIPPED          0x0200
# define PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
# define PE_IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800
# define PE_IMAGE_FILE_SYSTEM                  0x1000
# define PE_IMAGE_FILE_DLL                     0x2000
# define PE_IMAGE_FILE_UP_SYSTEM_ONLY          0x4000
# define PE_IMAGE_FILE_BYTES_REVERSED_HI       0x8000
} pe_image_file_header_t;

typedef struct pe_image_data_directory_t {
# define PE_IMAGE_DATA_DIRECTORY_SIZE 8

  uint32_t virtual_address;
  uint32_t size;
} pe_image_data_directory_t;

typedef struct pe32_image_optional_header_t {
  uint16_t magic;
# define PE_IMAGE_OPTIONAL_HEADER_MAGIC_NT_HDR32  0x10B
# define PE_IMAGE_OPTIONAL_HEADER_MAGIC_NT_HDR64  0x20B
# define PE_IMAGE_OPTIONAL_HEADER_MAGIC_ROM_HDR64 0x107

  uint8_t  major_linker_version;
  uint8_t  minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entrypoint;
  uint32_t base_of_code;
  uint32_t base_of_data;
  uint32_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t checksum;

  uint16_t subsystem;
# define PE_IMAGE_SUBSYSTEM_UNKNOWN                  0
# define PE_IMAGE_SUBSYSTEM_NATIVE                   1
# define PE_IMAGE_SUBSYSTEM_WINDOWS_GUI              2
# define PE_IMAGE_SUBSYSTEM_WINDOWS_CUI              3
# define PE_IMAGE_SUBSYSTEM_OS2_CUI                  5
# define PE_IMAGE_SUBSYSTEM_POSIX_CUI                7
# define PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           9
# define PE_IMAGE_SUBSYSTEM_EFI_APPLICATION          10
# define PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11
# define PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       12
# define PE_IMAGE_SUBSYSTEM_EFI_ROM                  13
# define PE_IMAGE_SUBSYSTEM_XBOX                     14
# define PE_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

  uint16_t dll_characteristics;
# define PE_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040
# define PE_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080
# define PE_IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100
# define PE_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200
# define PE_IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400
# define PE_IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800
# define PE_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000
# define PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

  uint32_t size_of_stack_reserve;
  uint32_t size_of_stack_commit;
  uint32_t size_of_heap_reserve;
  uint32_t size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;

# define PE_IMAGE_DATA_DIRECTORY_COUNT 16
  pe_image_data_directory_t data_directory[PE_IMAGE_DATA_DIRECTORY_COUNT];
# define PE_IMAGE_DIRECTORY_ENTRY_EXPORT          0
# define PE_IMAGE_DIRECTORY_ENTRY_IMPORT          1
# define PE_IMAGE_DIRECTORY_ENTRY_RESOURCE        2
# define PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
# define PE_IMAGE_DIRECTORY_ENTRY_SECURITY        4
# define PE_IMAGE_DIRECTORY_ENTRY_BASERELOC       5
# define PE_IMAGE_DIRECTORY_ENTRY_DEBUG           6
# define PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
# define PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
# define PE_IMAGE_DIRECTORY_ENTRY_TLS             9
# define PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
# define PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
# define PE_IMAGE_DIRECTORY_ENTRY_IAT            12
# define PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
# define PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
} pe32_image_optional_header_t;

typedef struct pe64_image_optional_header_t {
  uint16_t magic;
  /* PE_IMAGE_OPTIONAL_HEADER_MAGIC_* */

  uint8_t  major_linker_version;
  uint8_t  minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entrypoint;
  uint32_t base_of_code;
  uint64_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t checksum;

  uint16_t subsystem;
  /* PE_IMAGE_SUBSYSTEM_* */

  uint16_t dll_characteristics;
  /* PE_IMAGE_DLLCHARACTERISTICS_* */

  uint64_t size_of_stack_reserve;
  uint64_t size_of_stack_commit;
  uint64_t size_of_heap_reserve;
  uint64_t size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;

  pe_image_data_directory_t data_directory[PE_IMAGE_DATA_DIRECTORY_COUNT];
  /* PE_IMAGE_DATA_DIRECTORY_ENTRY_* */
} pe64_image_optional_header_t;

typedef union pe_image_optional_header_t {
  pe32_image_optional_header_t _32bit;
  pe64_image_optional_header_t _64bit;
} pe_image_optional_header_t;

typedef struct pe_nt_header_t {
  uint32_t signature;
# define PE_IMAGE_SIGNATURE_DOS    0x5A4D      /* MZ */
# define PE_IMAGE_SIGNATURE_OS2    0x454E      /* NE */
# define PE_IMAGE_SIGNATURE_OS2_LE 0x454C      /* LE */
# define PE_IMAGE_SIGNATURE_NT     0x00004550  /* PE */

  pe_image_file_header_t     file;
  pe_image_optional_header_t optional;
} pe_nt_header_t;

typedef struct pe_image_section_header_t {
# define PE_IMAGE_SECTION_HEADER_SIZE 40

# define PE_IMAGE_SECTION_NAME_SIZE 8
  uint8_t name[PE_IMAGE_SECTION_NAME_SIZE];

  union {
    uint32_t physical_address;
    uint32_t virtual_size;
  } misc;

  uint32_t virtual_address;
  uint32_t size_of_rawdate;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_linenumbers;
  uint16_t number_of_relocations;
  uint16_t number_of_linenumbers;

  uint32_t characteristics;
# define PE_IMAGE_SECTION_CONTAINS_CODE               0x00000020
# define PE_IMAGE_SECTION_CONTAINS_INITIALIZED_DATA   0x00000040
# define PE_IMAGE_SECTION_CONTAINS_UNINITIALIZED_DATA 0x00000080
# define PE_IMAGE_SECTION_LINK_INFO                   0x00000200
# define PE_IMAGE_SECTION_LINK_REMOVE                 0x00000800
# define PE_IMAGE_SECTION_LINK_COMDAT                 0x00001000
# define PE_IMAGE_SECTION_NO_DEFER_SPEC_EXC           0x00004000
# define PE_IMAGE_SECTION_GPREL                       0x00008000
# define PE_IMAGE_SECTION_ALIGN_1BYTES                0x00100000
# define PE_IMAGE_SECTION_ALIGN_2BYTES                0x00200000
# define PE_IMAGE_SECTION_ALIGN_4BYTES                0x00300000
# define PE_IMAGE_SECTION_ALIGN_8BYTES                0x00400000
# define PE_IMAGE_SECTION_ALIGN_16BYTES               0x00500000
# define PE_IMAGE_SECTION_ALIGN_32BYTES               0x00600000
# define PE_IMAGE_SECTION_ALIGN_64BYTES               0x00700000
# define PE_IMAGE_SECTION_ALIGN_128BYTES              0x00800000
# define PE_IMAGE_SECTION_ALIGN_256BYTES              0x00900000
# define PE_IMAGE_SECTION_ALIGN_512BYTES              0x00A00000
# define PE_IMAGE_SECTION_ALIGN_1024BYTES             0x00B00000
# define PE_IMAGE_SECTION_ALIGN_2048BYTES             0x00C00000
# define PE_IMAGE_SECTION_ALIGN_4096BYTES             0x00D00000
# define PE_IMAGE_SECTION_ALIGN_8192BYTES             0x00E00000
# define PE_IMAGE_SECTION_LINK_NRELOC_OVERFLOW        0x01000000
# define PE_IMAGE_SECTION_MEMORY_DISCARDABLE          0x02000000
# define PE_IMAGE_SECTION_MEMORY_NOT_CACHED           0x04000000
# define PE_IMAGE_SECTION_MEMORY_NOT_PAGED            0x08000000
# define PE_IMAGE_SECTION_MEMORY_SHARED               0x10000000
# define PE_IMAGE_SECTION_MEMORY_EXECUTE              0x20000000
# define PE_IMAGE_SECTION_MEMORY_READ                 0x40000000
# define PE_IMAGE_SECTION_MEMORY_WRITE                0x80000000
} pe_image_section_header_t;
