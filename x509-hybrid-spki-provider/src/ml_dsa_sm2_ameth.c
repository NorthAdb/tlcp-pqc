/*
 * ML-DSA-44-SM2 ASN1 Method
 * Provides pub_decode and pub_print for ML-DSA-44-SM2 hybrid keys
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/proverr.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>  /* For ASN1_buf_print */
#include <string.h>

/* For internal EVP structures */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "crypto/asn1.h"

/* ML-DSA-44 public key size */
#define ML_DSA_44_PUBLICKEYBYTES 1312
/* SM2 public key size (uncompressed format: 1 byte marker + 32 bytes X + 32 bytes Y) */
#define SM2_PUBLICKEYBYTES 65
/* Total hybrid key size */
#define ML_DSA_44_SM2_PUBLICKEYBYTES (ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES)

/* SPKI overhead for ML-DSA-44-SM2 */
#define ML_DSA_44_SM2_SPKI_OVERHEAD 22

/* Structure to hold ML-DSA-44-SM2 key data */
typedef struct {
    unsigned char *ml_dsa_pub;
    size_t ml_dsa_pub_len;
    EC_KEY *sm2_key;
} ML_DSA_SM2_KEY;

/* Free ML-DSA-44-SM2 key */
static void ml_dsa_sm2_key_free(ML_DSA_SM2_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->ml_dsa_pub);
    EC_KEY_free(key->sm2_key);
    OPENSSL_free(key);
}

/* Decode public key from X509_PUBKEY */
static int ml_dsa_sm2_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)
{
    const unsigned char *pk = NULL;
    int pklen;
    X509_ALGOR *algor = NULL;
    const ASN1_OBJECT *oid = NULL;
    int nid;
    ML_DSA_SM2_KEY *key = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *bn_ctx = NULL;
    int ret = 0;

    /* Get algorithm identifier */
    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, pubkey)) {
        ERR_raise(ERR_LIB_X509, X509_R_PUBLIC_KEY_DECODE_ERROR);
        return 0;
    }
    X509_ALGOR_get0(&oid, NULL, NULL, algor);
    if (oid == NULL) {
        ERR_raise(ERR_LIB_X509, X509_R_PUBLIC_KEY_DECODE_ERROR);
        return 0;
    }
    nid = OBJ_obj2nid(oid);

    /* Check if this is ML-DSA-44-SM2 */
    if (nid != NID_ML_DSA_44_SM2) {
        /* Not our key type, return 0 to let other methods try */
        return 0;
    }

    /* Expected total length: ML-DSA-44 key + SM2 key */
    /* Note: pk points to BIT STRING content (after the 1-byte unused bits header) */
    /* So pklen is the actual key data length, not including SPKI structure */
    int expected_key_len = ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES;
    if (pklen < expected_key_len) {
        ERR_raise_data(ERR_LIB_X509, X509_R_PUBLIC_KEY_DECODE_ERROR,
                      "Expected at least %d bytes, got %d",
                      expected_key_len, pklen);
        return 0;
    }

    /* Allocate key structure */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return 0;

    /* Extract ML-DSA-44 public key (first part of pk data) */
    key->ml_dsa_pub = OPENSSL_malloc(ML_DSA_44_PUBLICKEYBYTES);
    if (key->ml_dsa_pub == NULL)
        goto err;
    memcpy(key->ml_dsa_pub, pk, ML_DSA_44_PUBLICKEYBYTES);
    key->ml_dsa_pub_len = ML_DSA_44_PUBLICKEYBYTES;

    /* Create EC key for SM2 part */
    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;
    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (y == NULL)
        goto err;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto err;

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
        goto err;

    if (EC_KEY_set_group(ec_key, group) == 0)
        goto err;

    /* Parse SM2 public key (65 bytes: 1 byte marker + 32 bytes X + 32 bytes Y) */
    const unsigned char *sm2_pub_start = pk + ML_DSA_44_PUBLICKEYBYTES;
    /* Skip the 0x04 marker byte if present */
    if (sm2_pub_start[0] == 0x04) {
        sm2_pub_start++;
    }
    if (BN_bin2bn(sm2_pub_start, 32, x) == NULL ||
        BN_bin2bn(sm2_pub_start + 32, 32, y) == NULL)
        goto err;

    pub_point = EC_POINT_new(group);
    if (pub_point == NULL)
        goto err;

    if (EC_POINT_set_affine_coordinates(group, pub_point, x, y, bn_ctx) == 0)
        goto err;

    if (EC_KEY_set_public_key(ec_key, pub_point) == 0)
        goto err;

    key->sm2_key = ec_key;
    ec_key = NULL; /* Don't free, it's now owned by key */

    /* Set the key in EVP_PKEY */
    /* Note: EVP_PKEY_set_type may have already been called in x509_pubkey_decode,
     * but it should have found our ASN1 method. Ensure ameth is set correctly.
     */
    if (pkey->ameth == NULL) {
        if (EVP_PKEY_set_type(pkey, NID_ML_DSA_44_SM2) == 0)
            goto err;
    }
    
    pkey->pkey.ptr = key;
    ret = 1;

err:
    if (ret == 0) {
        ml_dsa_sm2_key_free(key);
        key = NULL;
    }
    EC_KEY_free(ec_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

/* Print public key */
static int ml_dsa_sm2_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                                 ASN1_PCTX *ctx)
{
    ML_DSA_SM2_KEY *key = (ML_DSA_SM2_KEY *)pkey->pkey.ptr;
    const EC_KEY *ec_key;
    const EC_POINT *pub_point;
    const EC_GROUP *group;
    unsigned char *combined_pub = NULL;
    size_t combined_len = 0;
    int ret = 0;

    if (key == NULL || key->sm2_key == NULL)
        return 0;

    ec_key = key->sm2_key;
    group = EC_KEY_get0_group(ec_key);
    pub_point = EC_KEY_get0_public_key(ec_key);

    if (group == NULL || pub_point == NULL)
        return 0;

    /* Get SM2 public key in uncompressed format (65 bytes: 0x04 + 32 bytes X + 32 bytes Y) */
    size_t sm2_pub_len = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED, &combined_pub, NULL);
    if (sm2_pub_len == 0 || sm2_pub_len != 65)
        goto err;

    /* Combine ML-DSA-44 public key (1312 bytes) + SM2 public key (65 bytes) = 1377 bytes total */
    combined_len = key->ml_dsa_pub_len + sm2_pub_len;
    unsigned char *full_pub = OPENSSL_malloc(combined_len);
    if (full_pub == NULL)
        goto err;

    /* Copy ML-DSA-44 public key first */
    memcpy(full_pub, key->ml_dsa_pub, key->ml_dsa_pub_len);
    /* Then copy SM2 public key */
    memcpy(full_pub + key->ml_dsa_pub_len, combined_pub, sm2_pub_len);

    /* Print in standard format: Public-Key: (bit) */
    /* Calculate bit size: ML-DSA-44 (1312 bytes) + SM2 (65 bytes) = 1377 bytes = 11016 bits */
    if (BIO_printf(bp, "%*sPublic-Key: (%zu bit)\n", indent, "", combined_len * 8) <= 0)
        goto err;

    /* Print pub: */
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        goto err;

    /* Print combined public key in hex format: 16 bytes per line with colons */
    for (size_t i = 0; i < combined_len; i++) {
        if (i % 16 == 0) {
            if (i > 0 && BIO_printf(bp, "\n") <= 0)
                goto err;
            if (BIO_printf(bp, "%*s", indent + 4, "") <= 0)
                goto err;
        }
        if (BIO_printf(bp, "%02x", full_pub[i]) <= 0)
            goto err;
        if (i < combined_len - 1 && BIO_printf(bp, ":") <= 0)
            goto err;
    }
    if (BIO_printf(bp, "\n") <= 0)
        goto err;

    ret = 1;

err:
    OPENSSL_free(full_pub);
    OPENSSL_free(combined_pub);
    return ret;
}

/* ASN1 method structure */
static EVP_PKEY_ASN1_METHOD ml_dsa_sm2_asn1_meth = {
    NID_ML_DSA_44_SM2,
    NID_ML_DSA_44_SM2,
    0,
    "ML-DSA-44-SM2",
    "ML-DSA-44-SM2 hybrid public key algorithm",

    ml_dsa_sm2_pub_decode,
    0, /* pub_encode */
    0, /* pub_cmp */
    ml_dsa_sm2_pub_print, /* pub_print */

    0, /* priv_decode */
    0, /* priv_encode */
    0, /* priv_print */

    0, /* pkey_size */
    0, /* pkey_bits */
    0, /* pkey_security_bits */

    0, /* param_decode */
    0, /* param_encode */
    0, /* param_missing */
    0, /* param_copy */
    0, /* param_cmp */
    0, /* param_print */
    0, /* sig_print */

    0, /* pkey_free */
    0, /* pkey_ctrl */
    0, /* old_priv_decode */
    0, /* old_priv_encode */

    0, /* item_verify */
    0, /* item_sign */

    0, /* siginf_set */
    0, /* pkey_check */
    0, /* pkey_public_check */
    0, /* pkey_param_check */
    0, /* set_priv_key */
    0, /* set_pub_key */
    0, /* get_priv_key */
    0, /* get_pub_key */

    0, /* dirty_cnt */
    0, /* export_to */
    0, /* import_from */
    0, /* copy */
    0, /* priv_decode_ex */
};

/* Register the ASN1 method */
int ml_dsa_sm2_register_ameth(void)
{
    int ret;
    
    /* Check if already registered */
    const EVP_PKEY_ASN1_METHOD *existing = EVP_PKEY_asn1_find(NULL, NID_ML_DSA_44_SM2);
    if (existing != NULL) {
        /* Already registered, return success */
        return 1;
    }
    
    ret = EVP_PKEY_asn1_add0(&ml_dsa_sm2_asn1_meth);
    return ret;
}
