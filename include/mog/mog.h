#ifndef MOG_H
#define MOG_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
# define MOG_API    extern "C"
#else
# define MOG_API
#endif

MOG_API void    mogReplaceFunction(void* dst, void* newAddr);
MOG_API void    mogReplaceSkip(void* dst, size_t len);
MOG_API void    mogReplaceNop(void* dst, size_t len);
MOG_API void*   mogVirtualAddress(uint32_t fixedAddr);

#endif
