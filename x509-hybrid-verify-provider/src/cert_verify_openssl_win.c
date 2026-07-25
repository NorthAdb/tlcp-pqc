/*
 * Windows: LD_PRELOAD interpose is not used; Tongsuo loads cert_verify.dll via
 * x509_pqc_hybrid_vfy.c and CERT_VERIFY_SO.
 */
#include "cert_verify.h"

void cert_verify_openssl_interpose_init(void)
{
}
