#include "./output.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>

#include "pe.h"

#define OUTPUT_HEADLINE(v) printf("\n#### "v" ####\n");

static void readpe_output_binary_(const uint8_t* body, size_t len) {
  assert(body != NULL || len == 0);

  const uint8_t* itr = body;
  const uint8_t* end = body + len;

  for (size_t i = 0; itr < end; ++i) {
    printf("%06"PRIX64":", (uint64_t) i*16);

    char str[16];
    for (size_t j = 0; j < 16 && itr < end; ++j) {
      if (j%2 == 0) printf(" ");
      str[j] = *(itr++);
      printf("%02"PRIX8, (uint8_t) str[j]);
      if (!isprint(str[j])) str[j] = '.';
    }
    printf("    %.16s\n", str);
  }
}

void readpe_output_dos_header(const pe_dos_header_t* dos_header) {
  assert(dos_header != NULL);

  OUTPUT_HEADLINE("DOS HEADER");

  printf("e_magic:  0x%04"PRIX16"\n", dos_header->e_magic);
  printf("e_lfanew: 0x%08"PRIX32"\n", dos_header->e_lfanew);
}

void readpe_output_dos_stub(const uint8_t* body, size_t len) {
  assert(body != NULL || len == 0);

  OUTPUT_HEADLINE("DOS STUB");

  printf("size: %zu bytes\n", len);
  readpe_output_binary_(body, len);
}
