#include "./output.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include "pe.h"

void readpe_output_dos_header(const pe_dos_header_t* dos_header) {
  assert(dos_header != NULL);

  printf("---- DOS HEADER ----\n");

  printf("e_magic:  0x%04"PRIX16"\n", dos_header->e_magic);
  printf("e_lfanew: 0x%08"PRIX32"\n", dos_header->e_lfanew);
}
