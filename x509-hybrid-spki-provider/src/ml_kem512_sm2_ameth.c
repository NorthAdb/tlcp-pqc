/*
 * ML-KEM-512-SM2 ASN1 Method (OID 1.2.156.10197.1.507.1)
 * Hybrid SPKI: ML-KEM-512 public key (800 bytes) + SM2 public key (65 bytes)
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <string.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "crypto/asn1.h"

#define ML_KEM_512_PUBLICKEYBYTES 800
#define SM2_PUBLICKEYBYTES 65
#define ML_KEM_512_SM2_PUBLICKEYBYTES (ML_KEM_512_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES)

typedef struct {
    unsigned char *ml_kem_pub;
    size_t ml_kem_pub_len;
    EC_KEY *sm2_key;
} ML_KEM_SM2_KEY;

static void ml_kem512_sm2_key_free(ML_KEM_SM2_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_free(key->ml_kem_pub);
    EC_KEY_free(key->sm2_key);
    OPENSSL_free(key);
}

static int ml_kem512_sm2_parse_sm2_point(EC_KEY **out_ec,
                                         const unsigned char *sm2_pub,
                                         size_t sm2_len)
{
    EC_GROUP *group = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *pub_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *bn_ctx = NULL;
    const unsigned char *p = sm2_pub;
    int ret = 0;

    if (out_ec == NULL || sm2_len < 64)
        return 0;
    if (sm2_len == 65 && p[0] == 0x04)
        p++;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;
    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (y == NULL)
        goto err;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    ec_key = EC_KEY_new();
    pub_point = EC_POINT_new(group);
    if (group == NULL || ec_key == NULL || pub_point == NULL)
        goto err;
    if (EC_KEY_set_group(ec_key, group) == 0)
        goto err;
    if (BN_bin2bn(p, 32, x) == NULL || BN_bin2bn(p + 32, 32, y) == NULL)
        goto err;
    if (EC_POINT_set_affine_coordinates(group, pub_point, x, y, bn_ctx) == 0)
        goto err;
    if (EC_KEY_set_public_key(ec_key, pub_point) == 0)
        goto err;

    *out_ec = ec_key;
    ec_key = NULL;
    ret = 1;

err:
    EC_KEY_free(ec_key);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int ml_kem512_sm2_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)
{
    const unsigned char *pk = NULL;
    int pklen;
    X509_ALGOR *algor = NULL;
    const ASN1_OBJECT *oid = NULL;
    ML_KEM_SM2_KEY *key = NULL;
    EC_KEY *ec_key = NULL;
    int ret = 0;

    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, pubkey)) {
        ERR_raise(ERR_LIB_X509, X509_R_PUBLIC_KEY_DECODE_ERROR);
        return 0;
    }
    X509_ALGOR_get0(&oid, NULL, NULL, algor);
    if (oid == NULL || OBJ_obj2nid(oid) != NID_ML_KEM_512_SM2)
        return 0;

    if (pklen > 0 && pk[0] == 0) {
        pk++;
        pklen--;
    }
    if (pklen < ML_KEM_512_SM2_PUBLICKEYBYTES) {
        ERR_raise_data(ERR_LIB_X509, X509_R_PUBLIC_KEY_DECODE_ERROR,
                       "ML-KEM-512-SM2: expected at least %d bytes, got %d",
                       ML_KEM_512_SM2_PUBLICKEYBYTES, pklen);
        return 0;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return 0;

    key->ml_kem_pub = OPENSSL_malloc(ML_KEM_512_PUBLICKEYBYTES);
    if (key->ml_kem_pub == NULL)
        goto err;
    memcpy(key->ml_kem_pub, pk, ML_KEM_512_PUBLICKEYBYTES);
    key->ml_kem_pub_len = ML_KEM_512_PUBLICKEYBYTES;

    if (!ml_kem512_sm2_parse_sm2_point(&ec_key, pk + ML_KEM_512_PUBLICKEYBYTES,
                                       (size_t)(pklen - ML_KEM_512_PUBLICKEYBYTES)))
        goto err;
    key->sm2_key = ec_key;
    ec_key = NULL;

    if (pkey->ameth == NULL && EVP_PKEY_set_type(pkey, NID_ML_KEM_512_SM2) == 0)
        goto err;
    pkey->pkey.ptr = key;
    ret = 1;

err:
    if (ret == 0)
        ml_kem512_sm2_key_free(key);
    EC_KEY_free(ec_key);
    return ret;
}

static int ml_kem512_sm2_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                                   ASN1_PCTX *ctx)
{
    ML_KEM_SM2_KEY *key = (ML_KEM_SM2_KEY *)pkey->pkey.ptr;
    unsigned char *sm2_buf = NULL;
    unsigned char *full_pub = NULL;
    size_t combined_len;
    size_t sm2_pub_len;
    int ret = 0;

    (void)ctx;
    if (key == NULL || key->sm2_key == NULL)
        return 0;

    sm2_pub_len = EC_KEY_key2buf(key->sm2_key, POINT_CONVERSION_UNCOMPRESSED,
                                &sm2_buf, NULL);
    if (sm2_pub_len != 65)
        goto err;

    combined_len = key->ml_kem_pub_len + sm2_pub_len;
    full_pub = OPENSSL_malloc(combined_len);
    if (full_pub == NULL)
        goto err;
    memcpy(full_pub, key->ml_kem_pub, key->ml_kem_pub_len);
    memcpy(full_pub + key->ml_kem_pub_len, sm2_buf, sm2_pub_len);

    if (BIO_printf(bp, "%*sPublic-Key: (%zu bit)\n", indent, "",
                   combined_len * 8) <= 0)
        goto err;
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        goto err;

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
    OPENSSL_free(sm2_buf);
    return ret;
}

static void ml_kem512_sm2_ameth_pkey_free(EVP_PKEY *pkey)
{
    if (pkey == NULL)
        return;
    ml_kem512_sm2_key_free((ML_KEM_SM2_KEY *)pkey->pkey.ptr);
    pkey->pkey.ptr = NULL;
}

static EVP_PKEY_ASN1_METHOD ml_kem512_sm2_asn1_meth = {
    NID_ML_KEM_512_SM2,
    NID_ML_KEM_512_SM2,
    0,
    "ML-KEM-512-SM2",
    "ML-KEM-512-SM2 hybrid public key algorithm",

    ml_kem512_sm2_pub_decode,
    0, /* pub_encode */
    0, /* pub_cmp */
    ml_kem512_sm2_pub_print,

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

    ml_kem512_sm2_ameth_pkey_free,
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

int ml_kem512_sm2_register_ameth(void)
{
    if (EVP_PKEY_asn1_find(NULL, NID_ML_KEM_512_SM2) != NULL)
        return 1;
    return EVP_PKEY_asn1_add0(&ml_kem512_sm2_asn1_meth);
}
