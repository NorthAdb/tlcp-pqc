#ifndef PQMAGIC_CONFIG_H
#define PQMAGIC_CONFIG_H

#define GLOBAL_NAMESPACE(s) pqmagic_global_##s 

#if defined(_WIN32) || defined(_WIN64)
# ifndef PQMAGIC_EXPORT
#  define PQMAGIC_EXPORT __declspec(dllexport)
# endif
#else
# define PQMAGIC_EXPORT
#endif

/* Object libs merged into one DLL must not use dllexport per translation unit */
#if defined(PQMAGIC_OBJECT_BUILD)
# undef PQMAGIC_EXPORT
# define PQMAGIC_EXPORT
#endif

#endif
