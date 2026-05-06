#ifndef NL4_MODULE_H
#define NL4_MODULE_H

#include <stdbool.h>

bool nl4_module_is_loaded(void);
int nl4_module_on(bool do_apply, int (*apply_fn)(void));
int nl4_module_stop(void);

#endif
