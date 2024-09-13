/*
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.  This file is offered as-is,
 * without any warranty.
 */

#ifndef GO_OPENPGP_H_
#define GO_OPENPGP_H_

#include <podman/openpgp.h>

#if defined(GO_OPENPGP_ENABLE_DLOPEN) && GO_OPENPGP_ENABLE_DLOPEN

#define FUNC(ret, name, args, cargs)		\
  ret go_##name args;
#define VOID_FUNC FUNC
#include "goopenpgpfuncs.h"
#undef VOID_FUNC
#undef FUNC

#define GO_OPENPGP_FUNC(name) go_##name

#else

#define GO_OPENPGP_FUNC(name) name

#endif /* GO_OPENPGP_ENABLE_DLOPEN */

/* Ensure SONAME to be loaded with dlopen FLAGS, and all the necessary
 * symbols are resolved.
 *
 * Returns 0 on success; negative error code otherwise.
 *
 * Note that this function is NOT thread-safe; when calling it from
 * multi-threaded programs, protect it with a locking mechanism.
 */
int go_openpgp_ensure_library (const char *soname, int flags);

/* Unload library and reset symbols.
 *
 * Note that this function is NOT thread-safe; when calling it from
 * multi-threaded programs, protect it with a locking mechanism.
 */
void go_openpgp_unload_library (void);

/* Return 1 if the library is loaded and usable.
 *
 * Note that this function is NOT thread-safe; when calling it from
 * multi-threaded programs, protect it with a locking mechanism.
 */
unsigned go_openpgp_is_usable (void);

#endif /* GO_OPENPGP_H_ */
