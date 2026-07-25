/*
 * Cross-platform dynamic library helpers for x509 PQC hybrid verification.
 */
#include "internal/cryptlib.h"
#include "x509_pqc_dso.h"

#include <string.h>

#ifdef _WIN32
# include <windows.h>

static char x509_pqc_dso_errbuf[256];

void *x509_pqc_dso_load(const char *path)
{
    return (void *)LoadLibraryA(path);
}

void *x509_pqc_dso_sym(void *handle, const char *name)
{
    if (handle == NULL)
        return NULL;
    return (void *)GetProcAddress((HMODULE)handle, name);
}

void x509_pqc_dso_unload(void *handle)
{
    if (handle != NULL)
        FreeLibrary((HMODULE)handle);
}

void *x509_pqc_dso_default_sym(const char *name)
{
    return x509_pqc_dso_sym(GetModuleHandle(NULL), name);
}

const char *x509_pqc_dso_error(void)
{
    DWORD err = GetLastError();

    x509_pqc_dso_errbuf[0] = '\0';
    if (err != 0) {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       x509_pqc_dso_errbuf, sizeof(x509_pqc_dso_errbuf), NULL);
    }
    if (x509_pqc_dso_errbuf[0] == '\0')
        OPENSSL_strlcpy(x509_pqc_dso_errbuf, "unknown error",
                        sizeof(x509_pqc_dso_errbuf));
    return x509_pqc_dso_errbuf;
}

#else

# include <dlfcn.h>

void *x509_pqc_dso_load(const char *path)
{
    return dlopen(path, RTLD_LAZY | RTLD_LOCAL);
}

void *x509_pqc_dso_sym(void *handle, const char *name)
{
    if (handle == NULL)
        return NULL;
    return dlsym(handle, name);
}

void x509_pqc_dso_unload(void *handle)
{
    if (handle != NULL)
        dlclose(handle);
}

void *x509_pqc_dso_default_sym(const char *name)
{
    return dlsym(RTLD_DEFAULT, name);
}

const char *x509_pqc_dso_error(void)
{
    const char *err = dlerror();

    return err != NULL ? err : "unknown error";
}

#endif

int x509_pqc_path_is_module(const char *path)
{
    const char *ext;

    if (path == NULL)
        return 0;
    ext = strrchr(path, '.');
    if (ext == NULL)
        return 0;
    return OPENSSL_strcasecmp(ext, X509_PQC_MOD_EXT) == 0;
}
