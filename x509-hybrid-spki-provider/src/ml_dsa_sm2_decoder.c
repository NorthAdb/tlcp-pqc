/*
 * ML-DSA-44-SM2 Provider
 * Decoder for ML-DSA-44-SM2 hybrid public keys
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/proverr.h>
#include <string.h>

/* ML-DSA-44 public key size */
#define ML_DSA_44_PUBLICKEYBYTES 1312
/* SM2 public key size (uncompressed point: 65 bytes, but we use 64 bytes for coordinates) */
#define SM2_PUBLICKEYBYTES 64
/* Total hybrid key size */
#define ML_DSA_44_SM2_PUBLICKEYBYTES (ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES)

/* SPKI overhead for ML-DSA-44-SM2 */
#define ML_DSA_44_SM2_SPKI_OVERHEAD 22

/* Forward declarations */
static OSSL_FUNC_decoder_newctx_fn ml_dsa_sm2_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn ml_dsa_sm2_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn ml_dsa_sm2_decoder_decode;
static OSSL_FUNC_decoder_does_selection_fn ml_dsa_sm2_decoder_does_selection;

/* Context structure */
typedef struct {
    void *provctx;
} ML_DSA_SM2_DECODER_CTX;

static void *ml_dsa_sm2_decoder_newctx(void *provctx)
{
    ML_DSA_SM2_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void ml_dsa_sm2_decoder_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int ml_dsa_sm2_decoder_does_selection(void *provctx, int selection)
{
    return (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | 
                        OSSL_KEYMGMT_SELECT_KEYPAIR)) != 0;
}

/* Decode ML-DSA-44-SM2 public key from SubjectPublicKeyInfo */
static int ml_dsa_sm2_decoder_decode(void *vctx, OSSL_CORE_BIO *cin,
                                     int selection,
                                     OSSL_CALLBACK *data_cb, void *data_cbarg,
                                     OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                     void *pw_cbarg)
{
    ML_DSA_SM2_DECODER_CTX *ctx = vctx;
    unsigned char *der = NULL, *derp;
    long len;
    X509_PUBKEY *xpub = NULL;
    X509_ALGOR *algor = NULL;
    const ASN1_OBJECT *oid = NULL;
    const unsigned char *pk = NULL;
    int pklen;
    int nid;
    OSSL_PARAM params[10], *p = params;
    int objtype = OSSL_OBJECT_PKEY;
    unsigned char *ml_dsa_pub = NULL;
    unsigned char *sm2_pub = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    const EC_POINT *pub_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *bn_ctx = NULL;
    int ok = 0;

    /* Read DER data */
    if (!ossl_read_der(ctx->provctx, cin, &der, &len))
        return 1;

    derp = der;
    xpub = ossl_d2i_X509_PUBKEY_INTERNAL((const unsigned char **)&derp, len,
                                         PROV_LIBCTX_OF(ctx->provctx));
    if (xpub == NULL)
        goto end;

    /* Get algorithm identifier */
    if (!X509_PUBKEY_get0_param(NULL, &pk, &pklen, &algor, xpub))
        goto end;
    X509_ALGOR_get0(&oid, NULL, NULL, algor);
    nid = OBJ_obj2nid(oid);

    /* Check if this is ML-DSA-44-SM2 */
    if (nid != NID_ML_DSA_44_SM2) {
        /* Not our key type */
        ok = 1;
        goto end;
    }

    /* Expected total length: SPKI overhead + ML-DSA-44 key + SM2 key */
    if (pklen < ML_DSA_44_SM2_SPKI_OVERHEAD + ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto end;
    }

    /* Extract ML-DSA-44 public key (skip SPKI overhead) */
    ml_dsa_pub = OPENSSL_malloc(ML_DSA_44_PUBLICKEYBYTES);
    if (ml_dsa_pub == NULL)
        goto end;
    memcpy(ml_dsa_pub, pk + ML_DSA_44_SM2_SPKI_OVERHEAD, ML_DSA_44_PUBLICKEYBYTES);

    /* Extract SM2 public key (after ML-DSA-44 key) */
    sm2_pub = OPENSSL_malloc(SM2_PUBLICKEYBYTES);
    if (sm2_pub == NULL)
        goto end;
    memcpy(sm2_pub, pk + ML_DSA_44_SM2_SPKI_OVERHEAD + ML_DSA_44_PUBLICKEYBYTES, 
           SM2_PUBLICKEYBYTES);

    /* Create EC key for SM2 part */
    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;
    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (y == NULL)
        goto end;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    ec_key = EC_KEY_new();
    if (ec_key == NULL)
        goto end;

    if (EC_KEY_set_group(ec_key, group) == 0)
        goto end;

    /* Parse SM2 public key (64 bytes: 32 bytes X + 32 bytes Y) */
    if (BN_bin2bn(sm2_pub, 32, x) == NULL ||
        BN_bin2bn(sm2_pub + 32, 32, y) == NULL)
        goto end;

    pub_point = EC_POINT_new(group);
    if (pub_point == NULL)
        goto end;

    if (EC_POINT_set_affine_coordinates(group, pub_point, x, y, bn_ctx) == 0)
        goto end;

    if (EC_KEY_set_public_key(ec_key, pub_point) == 0)
        goto end;

    /* Build OSSL_PARAM array for key data */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                            "ML-DSA-44-SM2", 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                            "SubjectPublicKeyInfo", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, len);
    *p++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
    
    /* Add ML-DSA-44 public key */
    *p++ = OSSL_PARAM_construct_octet_string("ml-dsa-44-public-key",
                                             ml_dsa_pub, ML_DSA_44_PUBLICKEYBYTES);
    
    /* Add SM2 public key coordinates */
    *p++ = OSSL_PARAM_construct_BN("sm2-public-key-x", x);
    *p++ = OSSL_PARAM_construct_BN("sm2-public-key-y", y);
    
    *p = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

end:
    OPENSSL_free(der);
    OPENSSL_free(ml_dsa_pub);
    OPENSSL_free(sm2_pub);
    EC_POINT_free((EC_POINT *)pub_point);
    EC_KEY_free(ec_key);
    EC_GROUP_free(group);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    ossl_X509_PUBKEY_INTERNAL_free(xpub);
    return ok;
}

/* Provider dispatch table */
static const OSSL_DISPATCH ml_dsa_sm2_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))ml_dsa_sm2_decoder_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))ml_dsa_sm2_decoder_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))ml_dsa_sm2_decoder_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))ml_dsa_sm2_decoder_decode },
    { 0, NULL }
};
