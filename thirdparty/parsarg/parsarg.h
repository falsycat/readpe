#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct {
  int                argc;
  const char* const* argv;

  const char* value;

  bool after_option;
} parsarg_t;

void
parsarg_initialize(
    parsarg_t* pa,
    int        argc,
    char**     argv
);

void
parsarg_deinitialize(
    parsarg_t* pa
);

const char*  /* NULLABLE */
parsarg_pop_name(
    parsarg_t* pa,
    size_t*    len
);

const char*  /* NULLABLE */
parsarg_pop_value(
    parsarg_t* pa
);

bool
parsarg_finished(
    const parsarg_t* pa
);
