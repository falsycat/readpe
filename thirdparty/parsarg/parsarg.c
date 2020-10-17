#include "./parsarg.h"

#include <assert.h>
#include <stddef.h>

void parsarg_initialize(parsarg_t* pa, int argc, char** argv) {
  assert(pa != NULL);

  *pa = (typeof(*pa)) {
    .argc = argc,
    .argv = (const char* const*) argv,
        /* Casting char** to const char* const* is not allowed in C... ;( */
  };
}

void parsarg_deinitialize(parsarg_t* pa) {
  assert(pa != NULL);
  (void) pa;

}

const char* parsarg_pop_name(parsarg_t* pa, size_t* len) {
  assert(pa  != NULL);
  assert(len != NULL);

  *len = 0;
  if (pa->argc <= 0 || pa->value != NULL || pa->after_option) {
    return NULL;
  }

  const char* v = *pa->argv;

  size_t offset = 0;
  while (v[offset] == '-') ++offset;

  if (offset == 0) return NULL;
  v += offset;

  --pa->argc;
  ++pa->argv;

  if (v[0] == 0) {
    pa->after_option = true;
    return NULL;
  }

  while (v[*len] != '=' && v[*len] != 0) ++*len;
  pa->value = (v[*len] == '='? &v[*len+1]: NULL);

  return *len > 0? v: NULL;
}

const char* parsarg_pop_value(parsarg_t* pa) {
  assert(pa != NULL);

  if (pa->value != NULL) {
    const char* v = pa->value;
    pa->value = NULL;
    return v;
  }

  if (pa->argc <= 0) return NULL;

  const char* v = *pa->argv;
  if (!pa->after_option && v[0] == '-') return NULL;

  --pa->argc;
  ++pa->argv;

  return v;
}

bool parsarg_finished(const parsarg_t* pa) {
  assert(pa != NULL);

  return pa->argc <= 0;
}
