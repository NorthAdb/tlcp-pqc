/*
 * Cross-platform dynamic library helpers for x509 PQC hybrid verification.
 */
#ifndef OSSL_X509_PQC_DSO_H
# define OSSL_X509_PQC_DSO_H

void *x509_pqc_dso_load(const char *path);
void *x509_pqc_dso_sym(void *handle, const char *name);
void  x509_pqc_dso_unload(void *handle);
void *x509_pqc_dso_default_sym(const char *name);
const char *x509_pqc_dso_error(void);

# ifdef _WIN32
#  define X509_PQC_MOD_EXT ".dll"
#  define X509_PQC_CERT_VERIFY_MOD "cert_verify.dll"
# else
#  define X509_PQC_MOD_EXT ".so"
#  define X509_PQC_CERT_VERIFY_MOD "cert_verify.so"
# endif

int x509_pqc_path_is_module(const char *path);

#endif
