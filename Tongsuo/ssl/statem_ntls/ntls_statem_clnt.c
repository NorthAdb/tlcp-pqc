/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "ntls_ssl_local.h"
#include "ntls_statem_local.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/md5.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include "crypto/ecc_kyber_hybrid.h"
#include "crypto/kyber.h"
#include "internal/x509_pqc_hybrid.h"

/* Helper function to print hex data */
static void print_hex_data(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    if (data == NULL || len == 0)
        return;
    fprintf(stderr, "[打印] %s (%zu bytes):\n", label, len);
    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02x", data[i]);
        if ((i + 1) % 32 == 0)
            fprintf(stderr, "\n");
        else if ((i + 1) % 16 == 0)
            fprintf(stderr, "  ");
    }
    if (len % 32 != 0)
        fprintf(stderr, "\n");
    fprintf(stderr, "\n");
}

/* Generic function to print key exchange information for client */
static void print_kex_info_client_ske(SSL *s, unsigned long alg_k)
{
    if (alg_k & SSL_kECCKyber) {
        /* Server's hybrid public key is stored in s->s3.tmp.pms */
        if (s->s3.tmp.pms != NULL && s->s3.tmp.pmslen > 0) {
            print_hex_data("客户端接收到的服务器混合公钥 (ECC+Kyber)", 
                          s->s3.tmp.pms, s->s3.tmp.pmslen);
        }
    } else if (alg_k & SSL_kSM2DHE) {
        /* Server's ephemeral public key is in s->s3.peer_tmp */
        if (s->s3.peer_tmp != NULL) {
            unsigned char *pubkey = NULL;
            size_t pubkey_len = 0;
            pubkey_len = EVP_PKEY_get1_encoded_public_key(s->s3.peer_tmp, &pubkey);
            if (pubkey != NULL && pubkey_len > 0) {
                print_hex_data("客户端接收到的服务器临时公钥 (SM2DHE)", pubkey, pubkey_len);
                OPENSSL_free(pubkey);
            }
        }
    }
}

static void print_kex_info_client_cke(SSL *s, unsigned long alg_k)
{
    if (alg_k & SSL_kECCKyber) {
        /* Shared secret is stored in s->s3.tmp.pms after encapsulation */
        if (s->s3.tmp.pms != NULL && s->s3.tmp.pmslen > 0) {
            print_hex_data("客户端封装得到的共享秘密 (ECC+Kyber)", 
                          s->s3.tmp.pms, s->s3.tmp.pmslen);
        }
    } else if (alg_k & (SSL_kRSA | SSL_kSM2)) {
        /* For RSA/SM2, PMS is encrypted and sent, we can't print it directly */
        /* But we can print it before encryption if needed */
    } else if (alg_k & SSL_kSM2DHE) {
        /* For SM2DHE, shared secret is in s->s3.tmp.pms */
        if (s->s3.tmp.pms != NULL && s->s3.tmp.pmslen > 0) {
            print_hex_data("客户端计算得到的共享秘密 (SM2DHE)", 
                          s->s3.tmp.pms, s->s3.tmp.pmslen);
        }
    }
}
#include <openssl/param_build.h>
#include "internal/cryptlib.h"
#include "internal/tlsgroups.h"

static MSG_PROCESS_RETURN tls_process_as_hello_retry_request(SSL *s, PACKET *pkt);

static ossl_inline int cert_req_allowed(SSL *s);
static int key_exchange_expected(SSL *s);
static int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                                    WPACKET *pkt);

/*
 * Is a CertificateRequest message allowed at the moment or not?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static ossl_inline int cert_req_allowed(SSL *s)
{
    /* TLS does not like anon-DH with client cert */
    if ((s->version > SSL3_VERSION
         && (s->s3.tmp.new_cipher->algorithm_auth & SSL_aNULL))
        || (s->s3.tmp.new_cipher->algorithm_auth & (SSL_aSRP | SSL_aPSK)))
        return 0;

    return 1;
}

/*
 * Should we expect the ServerKeyExchange message or not?
 *
 *  Return values are:
 *  1: Yes
 *  0: No
 */
static int key_exchange_expected(SSL *s)
{
    return 1;
}


/*
 * ossl_statem_client_read_transition_ntls() encapsulates the logic for the allowed
 * handshake state transitions when the client is reading messages from the
 * server. The message type that the server has sent is provided in |mt|. The
 * current state is in |s->statem.hand_state|.
 *
 * Return values are 1 for success (transition allowed) and  0 on error
 * (transition not allowed)
 */
int ossl_statem_client_read_transition_ntls(SSL *s, int mt)
{
    OSSL_STATEM *st = &s->statem;
    int ske_expected;

    /*
     * Note that after writing the first ClientHello we don't know what version
     * we are going to negotiate yet, so we don't take this branch until later.
     */

    switch (st->hand_state) {
    default:
        break;

    case TLS_ST_CW_CLNT_HELLO:
        if (mt == SSL3_MT_SERVER_HELLO) {
            st->hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }

        break;

    case TLS_ST_EARLY_DATA:
        /*
         * We've not actually selected TLSv1.3 yet, but we have sent early
         * data. The only thing allowed now is a ServerHello or a
         * HelloRetryRequest.
         */
        if (mt == SSL3_MT_SERVER_HELLO) {
            st->hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }
        break;

    case TLS_ST_CR_SRVR_HELLO:
        if (s->hit) {
            if (s->ext.ticket_expected) {
                if (mt == SSL3_MT_NEWSESSION_TICKET) {
                    st->hand_state = TLS_ST_CR_SESSION_TICKET;
                    return 1;
                }
            } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                st->hand_state = TLS_ST_CR_CHANGE;
                return 1;
            }
        } else {
            if (s->version >= NTLS_VERSION
                       && s->ext.session_secret_cb != NULL
                       && s->session->ext.tick != NULL
                       && mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * Normally, we can tell if the server is resuming the session
                 * from the session ID. EAP-FAST (RFC 4851), however, relies on
                 * the next server message after the ServerHello to determine if
                 * the server is resuming.
                 */
                s->hit = 1;
                st->hand_state = TLS_ST_CR_CHANGE;
                return 1;
            } else if (!(s->s3.tmp.new_cipher->algorithm_auth
                         & (SSL_aNULL | SSL_aSRP | SSL_aPSK))) {
                if (mt == SSL3_MT_CERTIFICATE) {
                    st->hand_state = TLS_ST_CR_CERT;
                    return 1;
                }
            } else {
                ske_expected = key_exchange_expected(s);
                /* SKE is optional for some PSK ciphersuites */
                if (ske_expected
                    || ((s->s3.tmp.new_cipher->algorithm_mkey & SSL_PSK)
                        && mt == SSL3_MT_SERVER_KEY_EXCHANGE)) {
                    if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                        st->hand_state = TLS_ST_CR_KEY_EXCH;
                        return 1;
                    }
                } else if (mt == SSL3_MT_CERTIFICATE_REQUEST
                           && cert_req_allowed(s)) {
                    st->hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                } else if (mt == SSL3_MT_SERVER_DONE) {
                    st->hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
        }
        break;

    case TLS_ST_CR_CERT:
        /*
         * The CertificateStatus message is optional even if
         * |ext.status_expected| is set
         */
        if (s->ext.status_expected && mt == SSL3_MT_CERTIFICATE_STATUS) {
            st->hand_state = TLS_ST_CR_CERT_STATUS;
            return 1;
        }
        /* Fall through */

    case TLS_ST_CR_CERT_STATUS:
        ske_expected = key_exchange_expected(s);
        /* SKE is optional for some PSK ciphersuites */
        if (ske_expected || ((s->s3.tmp.new_cipher->algorithm_mkey & SSL_PSK)
                             && mt == SSL3_MT_SERVER_KEY_EXCHANGE)) {
            if (mt == SSL3_MT_SERVER_KEY_EXCHANGE) {
                st->hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            }
            goto err;
        }
        /* Fall through */

    case TLS_ST_CR_KEY_EXCH:
        if (mt == SSL3_MT_CERTIFICATE_REQUEST) {
            if (cert_req_allowed(s)) {
                st->hand_state = TLS_ST_CR_CERT_REQ;
                return 1;
            }
            goto err;
        }
        /* Fall through */

    case TLS_ST_CR_CERT_REQ:
        if (mt == SSL3_MT_SERVER_DONE) {
            st->hand_state = TLS_ST_CR_SRVR_DONE;
            return 1;
        }
        break;

    case TLS_ST_CW_FINISHED:
        if (s->ext.ticket_expected) {
            if (mt == SSL3_MT_NEWSESSION_TICKET) {
                st->hand_state = TLS_ST_CR_SESSION_TICKET;
                return 1;
            }
        } else if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_SESSION_TICKET:
        if (mt == SSL3_MT_CHANGE_CIPHER_SPEC) {
            st->hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_CHANGE:
        if (mt == SSL3_MT_FINISHED) {
            st->hand_state = TLS_ST_CR_FINISHED;
            return 1;
        }
        break;

    case TLS_ST_OK:
        if (mt == SSL3_MT_HELLO_REQUEST) {
            st->hand_state = TLS_ST_CR_HELLO_REQ;
            return 1;
        }
        break;
    }

 err:
    SSLfatal_ntls(s, SSL3_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
    return 0;
}

/*
 * ossl_statem_client_write_transition_ntls() works out what handshake state to
 * move to next when the client is writing messages to be sent to the server.
 */
WRITE_TRAN ossl_statem_client_write_transition_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    /*
     * Note that immediately before/after a ClientHello we don't know what
     * version we are going to negotiate yet, so we don't take this branch until
     * later
     */

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return WRITE_TRAN_ERROR;

    case TLS_ST_OK:
        if (!s->renegotiate) {
            /*
             * We haven't requested a renegotiation ourselves so we must have
             * received a message from the server. Better read it.
             */
            return WRITE_TRAN_FINISHED;
        }
        /* Renegotiation */
        /* fall thru */
    case TLS_ST_BEFORE:
        st->hand_state = TLS_ST_CW_CLNT_HELLO;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CLNT_HELLO:
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING) {
            /*
             * We are assuming this is a TLSv1.3 connection, although we haven't
             * actually selected a version yet.
             */
            if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0)
                st->hand_state = TLS_ST_CW_CHANGE;
            else
                st->hand_state = TLS_ST_EARLY_DATA;
            return WRITE_TRAN_CONTINUE;
        }
        /*
         * No transition at the end of writing because we don't know what
         * we will be sent
         */
        return WRITE_TRAN_FINISHED;

    case TLS_ST_CR_SRVR_HELLO:
        /*
         * We only get here in TLSv1.3. We just received an HRR, so issue a
         * CCS unless middlebox compat mode is off, or we already issued one
         * because we did early data.
         */
        if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
                && s->early_data_state != SSL_EARLY_DATA_FINISHED_WRITING)
            st->hand_state = TLS_ST_CW_CHANGE;
        else
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_EARLY_DATA:
        return WRITE_TRAN_FINISHED;

    case TLS_ST_CR_SRVR_DONE:
        if (s->s3.tmp.cert_req)
            st->hand_state = TLS_ST_CW_CERT;
        else
            st->hand_state = TLS_ST_CW_KEY_EXCH;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CERT:
        st->hand_state = TLS_ST_CW_KEY_EXCH;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_KEY_EXCH:
        /*
         * For TLS, cert_req is set to 2, so a cert chain of nothing is
         * sent, but no verify packet is sent
         */
        /*
         * XXX: For now, we do not support client authentication in ECDH
         * cipher suites with ECDH (rather than ECDSA) certificates. We
         * need to skip the certificate verify message when client's
         * ECDH public key is sent inside the client certificate.
         */
        if (s->s3.tmp.cert_req == 1) {
            st->hand_state = TLS_ST_CW_CERT_VRFY;
        } else {
            st->hand_state = TLS_ST_CW_CHANGE;
        }
        if (s->s3.flags & TLS1_FLAGS_SKIP_CERT_VERIFY) {
            st->hand_state = TLS_ST_CW_CHANGE;
        }
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CERT_VRFY:
        st->hand_state = TLS_ST_CW_CHANGE;
        return WRITE_TRAN_CONTINUE;

    case TLS_ST_CW_CHANGE:
        if (s->hello_retry_request == SSL_HRR_PENDING) {
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
        } else if (s->early_data_state == SSL_EARLY_DATA_CONNECTING) {
            st->hand_state = TLS_ST_EARLY_DATA;
        } else {
#if defined(OPENSSL_NO_NEXTPROTONEG)
            st->hand_state = TLS_ST_CW_FINISHED;
#else
            if (s->s3.npn_seen)
                st->hand_state = TLS_ST_CW_NEXT_PROTO;
            else
                st->hand_state = TLS_ST_CW_FINISHED;
#endif
        }
        return WRITE_TRAN_CONTINUE;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    case TLS_ST_CW_NEXT_PROTO:
        st->hand_state = TLS_ST_CW_FINISHED;
        return WRITE_TRAN_CONTINUE;
#endif

    case TLS_ST_CW_FINISHED:
        if (s->hit) {
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        } else {
            return WRITE_TRAN_FINISHED;
        }

    case TLS_ST_CR_FINISHED:
        if (s->hit) {
            st->hand_state = TLS_ST_CW_CHANGE;
            return WRITE_TRAN_CONTINUE;
        } else {
            st->hand_state = TLS_ST_OK;
            return WRITE_TRAN_CONTINUE;
        }

    case TLS_ST_CR_HELLO_REQ:
        /*
         * If we can renegotiate now then do so, otherwise wait for a more
         * convenient time.
         */
        if (ssl3_renegotiate_check(s, 1)) {
            if (!tls_setup_handshake_ntls(s)) {
                /* SSLfatal_ntls() already called */
                return WRITE_TRAN_ERROR;
            }
            st->hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;
        }
        st->hand_state = TLS_ST_OK;
        return WRITE_TRAN_CONTINUE;
    }
}

/*
 * Perform any pre work that needs to be done prior to sending a message from
 * the client to the server.
 */
WORK_STATE ossl_statem_client_pre_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* No pre work to be done */
        break;

    case TLS_ST_CW_CLNT_HELLO:
        s->shutdown = 0;
        break;

    case TLS_ST_CW_CHANGE:
        break;

    case TLS_ST_PENDING_EARLY_DATA_END:
        /*
         * If we've been called by SSL_do_handshake()/SSL_write(), or we did not
         * attempt to write early data before calling SSL_read() then we press
         * on with the handshake. Otherwise we pause here.
         */
        if (s->early_data_state == SSL_EARLY_DATA_FINISHED_WRITING
                || s->early_data_state == SSL_EARLY_DATA_NONE)
            return WORK_FINISHED_CONTINUE;
        /* Fall through */

    case TLS_ST_EARLY_DATA:
        return tls_finish_handshake_ntls(s, wst, 0, 1);

    case TLS_ST_OK:
        /* Calls SSLfatal_ntls() as required */
        return tls_finish_handshake_ntls(s, wst, 1, 1);
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Perform any work that needs to be done after sending a message from the
 * client to the server.
 */
WORK_STATE ossl_statem_client_post_work_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    s->init_num = 0;

    switch (st->hand_state) {
    default:
        /* No post work to be done */
        break;

    case TLS_ST_CW_CLNT_HELLO:
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
                && s->max_early_data > 0) {
            /*
             * We haven't selected TLSv1.3 yet so we don't call the change
             * cipher state function associated with the SSL_METHOD. Instead
             * we call tls13_change_cipher_state() directly.
             */
            if ((s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) == 0) {
                if (!tls13_change_cipher_state(s,
                            SSL3_CC_EARLY | SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
                    /* SSLfatal_ntls() already called */
                    return WORK_ERROR;
                }
            }
            /* else we're in compat mode so we delay flushing until after CCS */
        } else if (!statem_flush_ntls(s)) {
            return WORK_MORE_A;
        }

        break;

    case TLS_ST_CW_END_OF_EARLY_DATA:
        /*
         * We set the enc_write_ctx back to NULL because we may end up writing
         * in cleartext again if we get a HelloRetryRequest from the server.
         */
        EVP_CIPHER_CTX_free(s->enc_write_ctx);
        s->enc_write_ctx = NULL;
        break;

    case TLS_ST_CW_KEY_EXCH:
        if (tls_client_key_exchange_post_work_ntls(s) == 0) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;

    case TLS_ST_CW_CHANGE:
        if (s->hello_retry_request == SSL_HRR_PENDING)
            break;
        if (s->early_data_state == SSL_EARLY_DATA_CONNECTING
                    && s->max_early_data > 0) {
            /*
             * We haven't selected TLSv1.3 yet so we don't call the change
             * cipher state function associated with the SSL_METHOD. Instead
             * we call tls13_change_cipher_state() directly.
             */
            if (!tls13_change_cipher_state(s,
                        SSL3_CC_EARLY | SSL3_CHANGE_CIPHER_CLIENT_WRITE))
                return WORK_ERROR;
            break;
        }
        s->session->cipher = s->s3.tmp.new_cipher;
        if (s->session->cipher != NULL) {
            fprintf(stderr, "[NTLS Client] Setting cipher: %s (0x%04X)\n",
                   SSL_CIPHER_get_name(s->session->cipher),
                   (unsigned int)(s->session->cipher->id & 0xFFFF));
        } else {
            fprintf(stderr, "[NTLS Client] ERROR: new_cipher is NULL when setting session->cipher!\n");
        }
#ifdef OPENSSL_NO_COMP
        s->session->compress_meth = 0;
#else
        if (s->s3.tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3.tmp.new_compression->id;
#endif
        if (!s->method->ssl3_enc->setup_key_block(s)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }

        if (!s->method->ssl3_enc->change_cipher_state(s,
                                          SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }

        break;

    case TLS_ST_CW_FINISHED:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_B;
        break;

    case TLS_ST_CW_KEY_UPDATE:
        if (statem_flush_ntls(s) != 1)
            return WORK_MORE_A;
        if (!tls13_update_key(s, 1)) {
            /* SSLfatal_ntls() already called */
            return WORK_ERROR;
        }
        break;
    }

    return WORK_FINISHED_CONTINUE;
}

/*
 * Get the message construction function and message type for sending from the
 * client
 *
 * Valid return values are:
 *   1: Success
 *   0: Error
 */
int ossl_statem_client_construct_message_ntls(SSL *s, WPACKET *pkt,
                                         confunc_f *confunc, int *mt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_HANDSHAKE_STATE);
        return 0;

    case TLS_ST_CW_CHANGE:
        *confunc = tls_construct_change_cipher_spec_ntls;
        *mt = SSL3_MT_CHANGE_CIPHER_SPEC;
        break;

    case TLS_ST_CW_CLNT_HELLO:
        *confunc = tls_construct_client_hello_ntls;
        *mt = SSL3_MT_CLIENT_HELLO;
        break;

    case TLS_ST_CW_END_OF_EARLY_DATA:
        *confunc = tls_construct_end_of_early_data_ntls;
        *mt = SSL3_MT_END_OF_EARLY_DATA;
        break;

    case TLS_ST_PENDING_EARLY_DATA_END:
        *confunc = NULL;
        *mt = SSL3_MT_DUMMY;
        break;

    case TLS_ST_CW_CERT:
        *confunc = tls_construct_client_certificate_ntls;
        *mt = SSL3_MT_CERTIFICATE;
        break;

    case TLS_ST_CW_KEY_EXCH:
        *confunc = tls_construct_client_key_exchange_ntls;
        *mt = SSL3_MT_CLIENT_KEY_EXCHANGE;
        break;

    case TLS_ST_CW_CERT_VRFY:
        *confunc = tls_construct_cert_verify_ntls;
        *mt = SSL3_MT_CERTIFICATE_VERIFY;
        break;

#if !defined(OPENSSL_NO_NEXTPROTONEG)
    case TLS_ST_CW_NEXT_PROTO:
        *confunc = tls_construct_next_proto_ntls;
        *mt = SSL3_MT_NEXT_PROTO;
        break;
#endif
    case TLS_ST_CW_FINISHED:
        *confunc = tls_construct_finished_ntls;
        *mt = SSL3_MT_FINISHED;
        break;
    }
    return 1;
}

/*
 * Returns the maximum allowed length for the current message that we are
 * reading. Excludes the message header.
 */
size_t ossl_statem_client_max_message_size_ntls(SSL *s)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        return 0;

    case TLS_ST_CR_SRVR_HELLO:
        return SERVER_HELLO_MAX_LENGTH;

    case TLS_ST_CR_CERT:
        return s->max_cert_list;

    case TLS_ST_CR_CERT_STATUS:
        return SSL3_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_KEY_EXCH:
        return SERVER_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_CR_CERT_REQ:
        /*
         * Set to s->max_cert_list for compatibility with previous releases. In
         * practice these messages can get quite long if servers are configured
         * to provide a long list of acceptable CAs
         */
        return s->max_cert_list;

    case TLS_ST_CR_SRVR_DONE:
        return SERVER_HELLO_DONE_MAX_LENGTH;

    case TLS_ST_CR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_CR_SESSION_TICKET:
        return SESSION_TICKET_MAX_LENGTH_TLS12;

    case TLS_ST_CR_FINISHED:
        return FINISHED_MAX_LENGTH;

    case TLS_ST_CR_ENCRYPTED_EXTENSIONS:
        return ENCRYPTED_EXTENSIONS_MAX_LENGTH;

    case TLS_ST_CR_KEY_UPDATE:
        return KEY_UPDATE_MAX_LENGTH;
    }
}

/*
 * Process a message that the client has received from the server.
 */
MSG_PROCESS_RETURN ossl_statem_client_process_message_ntls(SSL *s, PACKET *pkt)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;

    case TLS_ST_CR_SRVR_HELLO:
        return tls_process_server_hello_ntls(s, pkt);

    case TLS_ST_CR_CERT:
        return tls_process_server_certificate_ntls(s, pkt);

    case TLS_ST_CR_CERT_STATUS:
        return tls_process_cert_status_ntls(s, pkt);

    case TLS_ST_CR_KEY_EXCH:
        return tls_process_key_exchange_ntls(s, pkt);

    case TLS_ST_CR_CERT_REQ:
        return tls_process_certificate_request_ntls(s, pkt);

    case TLS_ST_CR_SRVR_DONE:
        return tls_process_server_done_ntls(s, pkt);

    case TLS_ST_CR_CHANGE:
        return tls_process_change_cipher_spec_ntls(s, pkt);

    case TLS_ST_CR_SESSION_TICKET:
        return tls_process_new_session_ticket_ntls(s, pkt);

    case TLS_ST_CR_FINISHED:
        return tls_process_finished_ntls(s, pkt);

    case TLS_ST_CR_HELLO_REQ:
        return tls_process_hello_req_ntls(s, pkt);
    }
}

/*
 * Perform any further processing required following the receipt of a message
 * from the server
 */
WORK_STATE ossl_statem_client_post_process_message_ntls(SSL *s, WORK_STATE wst)
{
    OSSL_STATEM *st = &s->statem;

    switch (st->hand_state) {
    default:
        /* Shouldn't happen */
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return WORK_ERROR;

    case TLS_ST_CR_CERT:
        return tls_post_process_server_certificate_ntls(s, wst);

    case TLS_ST_CR_CERT_REQ:
        return tls_prepare_client_certificate_ntls(s, wst);
    }
}

int tls_construct_client_hello_ntls(SSL *s, WPACKET *pkt)
{
    unsigned char *p;
    size_t sess_id_len;
    SSL_SESSION *sess = s->session;
    unsigned char *session_id;
    
    fprintf(stderr, "[NTLS Client] >>> Constructing ClientHello\n");

    if (sess == NULL
            || !ssl_version_supported_ntls(s, sess->ssl_version, NULL)
            || !SSL_SESSION_is_resumable(sess)) {
        if (!ssl_get_new_session(s, 0)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }
    /* else use the pre-loaded session */

    p = s->s3.client_random;

    if (ssl_fill_hello_random(s, 0, p, sizeof(s->s3.client_random),
                              DOWNGRADE_NONE) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*-
     * version indicates the negotiated version: for example from
     * an SSLv2/v3 compatible client hello). The client_version
     * field is the maximum version we permit and it is also
     * used in RSA encrypted premaster secrets. Some servers can
     * choke if we initially report a higher version then
     * renegotiate to a lower one in the premaster secret. This
     * didn't happen with TLS 1.0 as most servers supported it
     * but it can with TLS 1.1 or later if the server only supports
     * 1.0.
     *
     * Possible scenario with previous logic:
     *      1. Client hello indicates TLS 1.2
     *      2. Server hello says TLS 1.0
     *      3. RSA encrypted premaster secret uses 1.2.
     *      4. Handshake proceeds using TLS 1.0.
     *      5. Server sends hello request to renegotiate.
     *      6. Client hello indicates TLS v1.0 as we now
     *         know that is maximum server supports.
     *      7. Server chokes on RSA encrypted premaster secret
     *         containing version 1.0.
     *
     * For interoperability it should be OK to always use the
     * maximum version we support in client hello and then rely
     * on the checking of version to ensure the servers isn't
     * being inconsistent: for example initially negotiating with
     * TLS 1.0 and renegotiating with TLS 1.2. We do this by using
     * client_version in client hello and not resetting it to
     * the negotiated version.
     *
     * For TLS 1.3 we always set the ClientHello version to 1.2 and rely on the
     * supported_versions extension for the real supported versions.
     */
    if (!WPACKET_put_bytes_u16(pkt, s->client_version)
            || !WPACKET_memcpy(pkt, s->s3.client_random, SSL3_RANDOM_SIZE)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Session ID */
    session_id = s->session->session_id;
    if (s->new_session || s->session->ssl_version == TLS1_3_VERSION) {
        if (s->version == TLS1_3_VERSION
                && (s->options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0) {
            sess_id_len = sizeof(s->tmp_session_id);
            s->tmp_session_id_len = sess_id_len;
            session_id = s->tmp_session_id;
            if (s->hello_retry_request == SSL_HRR_NONE
                    && RAND_bytes_ex(s->ctx->libctx, s->tmp_session_id,
                                     sess_id_len, 0) <= 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            sess_id_len = 0;
        }
    } else {
        assert(s->session->session_id_length <= sizeof(s->session->session_id));
        sess_id_len = s->session->session_id_length;
        if (s->version == TLS1_3_VERSION) {
            s->tmp_session_id_len = sess_id_len;
            memcpy(s->tmp_session_id, s->session->session_id, sess_id_len);
        }
    }
    if (!WPACKET_start_sub_packet_u8(pkt)
            || (sess_id_len != 0 && !WPACKET_memcpy(pkt, session_id,
                                                    sess_id_len))
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Ciphers supported */
    if (!WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), pkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }
    if (!WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* COMPRESSION */
    if (!WPACKET_start_sub_packet_u8(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Add the NULL method */
    if (!WPACKET_put_bytes_u8(pkt, 0) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* TLS extensions */
    if (!tls_construct_extensions_ntls(s, pkt, SSL_EXT_CLIENT_HELLO, NULL, 0)) {
        /* SSLfatal() already called */
        return 0;
    }

    return 1;
}

static int set_client_ciphersuite_ntls(SSL *s, const unsigned char *cipherchars)
{
    STACK_OF(SSL_CIPHER) *sk;
    const SSL_CIPHER *c;
    int i;

    c = ssl_get_cipher_by_char(s, cipherchars, 0);
    if (c == NULL) {
        /* unknown cipher */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_UNKNOWN_CIPHER_RETURNED);
        return 0;
    }
    /*
     * If it is a disabled cipher we either didn't send it in client hello,
     * or it's not allowed for the selected protocol. So we return an error.
     */
    if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_CHECK, 1)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_WRONG_CIPHER_RETURNED);
        return 0;
    }

    sk = ssl_get_ciphers_by_id(s);
    i = sk_SSL_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_WRONG_CIPHER_RETURNED);
        return 0;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (s->session->cipher != NULL)
        s->session->cipher_id = s->session->cipher->id;
    if (s->hit && (s->session->cipher_id != c->id)) {
        /*
         * Prior to TLSv1.3 resuming a session always meant using the same
         * ciphersuite.
         */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                      SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
        return 0;
    }
    s->s3.tmp.new_cipher = c;

    return 1;
}

MSG_PROCESS_RETURN tls_process_server_hello_ntls(SSL *s, PACKET *pkt)
{
    PACKET session_id, extpkt;
    size_t session_id_len;
    const unsigned char *cipherchars;
    int hrr = 0;
    unsigned int compression;
    unsigned int sversion;
    unsigned int context;
    RAW_EXTENSION *extensions = NULL;
    
    fprintf(stderr, "[NTLS Client] <<< Processing ServerHello\n");

    if (!PACKET_get_net_2(pkt, &sversion)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /* load the server random */
    if (s->version == TLS1_3_VERSION
            && sversion == TLS1_2_VERSION
            && PACKET_remaining(pkt) >= SSL3_RANDOM_SIZE
            && memcmp(hrrrandom_ntls, PACKET_data(pkt), SSL3_RANDOM_SIZE) == 0) {
        s->hello_retry_request = SSL_HRR_PENDING;
        hrr = 1;
        if (!PACKET_forward(pkt, SSL3_RANDOM_SIZE)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
            goto err;
        }
    } else {
        if (!PACKET_copy_bytes(pkt, s->s3.server_random, SSL3_RANDOM_SIZE)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
            goto err;
        }
    }

    /* Get the session-id. */
    if (!PACKET_get_length_prefixed_1(pkt, &session_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    session_id_len = PACKET_remaining(&session_id);
    if (session_id_len > sizeof(s->session->session_id)
        || session_id_len > SSL3_SESSION_ID_SIZE) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_SSL3_SESSION_ID_TOO_LONG);
        goto err;
    }

    if (!PACKET_get_bytes(pkt, &cipherchars, TLS_CIPHER_LEN)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    if (!PACKET_get_1(pkt, &compression)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /* TLS extensions */
    if (PACKET_remaining(pkt) == 0 && !hrr) {
        PACKET_null_init(&extpkt);
    } else if (!PACKET_as_length_prefixed_2(pkt, &extpkt)
               || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH);
        goto err;
    }

    if (!hrr) {
        if (!tls_collect_extensions_ntls(s, &extpkt,
                                    SSL_EXT_TLS1_2_SERVER_HELLO
                                    | SSL_EXT_TLS1_3_SERVER_HELLO,
                                    &extensions, NULL, 1)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        if (!ssl_choose_client_version_ntls(s, sversion, extensions)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    }

    if (hrr) {
        if (compression != 0) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                     SSL_R_INVALID_COMPRESSION_ALGORITHM);
            goto err;
        }

        if (session_id_len != s->tmp_session_id_len
                || memcmp(PACKET_data(&session_id), s->tmp_session_id,
                          session_id_len) != 0) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_INVALID_SESSION_ID);
            goto err;
        }
    }

    if (hrr) {
        if (!set_client_ciphersuite_ntls(s, cipherchars)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }

        return tls_process_as_hello_retry_request(s, &extpkt);
    }

    /*
     * Now we have chosen the version we need to check again that the extensions
     * are appropriate for this version.
     */
    context = SSL_EXT_TLS1_2_SERVER_HELLO;
    if (!tls_validate_all_contexts_ntls(s, context, extensions)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_EXTENSION);
        goto err;
    }

    s->hit = 0;

    /*
    * Check if we can resume the session based on external pre-shared
    * secret. EAP-FAST (RFC 4851) supports two types of session resumption.
    * Resumption based on server-side state works with session IDs.
    * Resumption based on pre-shared Protected Access Credentials (PACs)
    * works by overriding the SessionTicket extension at the application
    * layer, and does not send a session ID. (We do not know whether
    * EAP-FAST servers would honour the session ID.) Therefore, the session
    * ID alone is not a reliable indicator of session resumption, so we
    * first check if we can resume, and later peek at the next handshake
    * message to see if the server wants to resume.
    */
    if (s->version >= NTLS_VERSION
            && s->ext.session_secret_cb != NULL && s->session->ext.tick) {
        const SSL_CIPHER *pref_cipher = NULL;
        /*
         * s->session->master_key_length is a size_t, but this is an int for
         * backwards compat reasons
         */
        int master_key_length;
        master_key_length = sizeof(s->session->master_key);
        if (s->ext.session_secret_cb(s, s->session->master_key,
                                     &master_key_length,
                                     NULL, &pref_cipher,
                                     s->ext.session_secret_cb_arg)
                                     && master_key_length > 0) {
            s->session->master_key_length = master_key_length;
            s->session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, cipherchars, 0);
        } else {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (session_id_len != 0
            && session_id_len == s->session->session_id_length
            && memcmp(PACKET_data(&session_id), s->session->session_id,
                      session_id_len) == 0)
        s->hit = 1;

    if (s->hit) {
        if (s->sid_ctx_length != s->session->sid_ctx_length
                || memcmp(s->session->sid_ctx, s->sid_ctx, s->sid_ctx_length)) {
            /* actually a client application bug */
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                          SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
            goto err;
        }
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't resume, make a new SSL_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (s->session->session_id_length > 0) {
            ssl_tsan_counter(s->session_ctx, &s->session_ctx->stats.sess_miss);
            if (!ssl_get_new_session(s, 0)) {
                /* SSLfatal_ntls() already called */
                goto err;
            }
        }

        s->session->ssl_version = s->version;
        /*
         * In TLSv1.2 and below we save the session id we were sent so we can
         * resume it later. In TLSv1.3 the session id we were sent is just an
         * echo of what we originally sent in the ClientHello and should not be
         * used for resumption.
         */
        s->session->session_id_length = session_id_len;
        /* session_id_len could be 0 */
        if (session_id_len > 0)
            memcpy(s->session->session_id, PACKET_data(&session_id),
                    session_id_len);
    }

    /* Session version and negotiated protocol version should match */
    if (s->version != s->session->ssl_version) {
        SSLfatal_ntls(s, SSL_AD_PROTOCOL_VERSION,
                 SSL_R_SSL_SESSION_VERSION_MISMATCH);
        goto err;
    }
    /*
     * Now that we know the version, update the check to see if it's an allowed
     * version.
     */
    s->s3.tmp.min_ver = s->version;
    s->s3.tmp.max_ver = s->version;

    if (!set_client_ciphersuite_ntls(s, cipherchars)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }
    if (s->s3.tmp.new_cipher != NULL) {
        fprintf(stderr, "[NTLS Client] Received cipher from server: %s (0x%04X)\n",
               SSL_CIPHER_get_name(s->s3.tmp.new_cipher),
               (unsigned int)(s->s3.tmp.new_cipher->id & 0xFFFF));
    }

    if (compression != 0) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
		              SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        goto err;
    }
    /*
     * If compression is disabled we'd better not try to resume a session
     * using compression.
     */
    if (s->session->compress_meth != 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_INCONSISTENT_COMPRESSION);
        goto err;
    }


    if (!tls_parse_all_extensions_ntls(s, context, extensions, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /*
     * In TLSv1.3 we have some post-processing to change cipher state, otherwise
     * we're done with this message
     */
    OPENSSL_free(extensions);
    return MSG_PROCESS_CONTINUE_READING;
 err:
    OPENSSL_free(extensions);
    return MSG_PROCESS_ERROR;
}

static MSG_PROCESS_RETURN tls_process_as_hello_retry_request(SSL *s,
                                                             PACKET *extpkt)
{
    RAW_EXTENSION *extensions = NULL;

    /*
     * If we were sending early_data then the enc_write_ctx is now invalid and
     * should not be used.
     */
    EVP_CIPHER_CTX_free(s->enc_write_ctx);
    s->enc_write_ctx = NULL;

    if (!tls_collect_extensions_ntls(s, extpkt, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST,
                                &extensions, NULL, 1)
            || !tls_parse_all_extensions_ntls(s, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST,
                                         extensions, NULL, 0, 1)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    OPENSSL_free(extensions);
    extensions = NULL;

    if (s->ext.tls13_cookie_len == 0 && s->s3.tmp.pkey != NULL) {
        /*
         * We didn't receive a cookie or a new key_share so the next
         * ClientHello will not change
         */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_NO_CHANGE_FOLLOWING_HRR);
        goto err;
    }

    /*
     * Re-initialise the Transcript Hash. We're going to prepopulate it with
     * a synthetic message_hash in place of ClientHello1.
     */
    if (!create_synthetic_message_hash_ntls(s, NULL, 0, NULL, 0)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /*
     * Add this message to the Transcript Hash. Normally this is done
     * automatically prior to the message processing stage. However due to the
     * need to create the synthetic message hash, we defer that step until now
     * for HRR messages.
     */
    if (!ssl3_finish_mac(s, (unsigned char *)s->init_buf->data,
                                s->init_num + SSL3_HM_HEADER_LENGTH)) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    return MSG_PROCESS_FINISHED_READING;
 err:
    OPENSSL_free(extensions);
    return MSG_PROCESS_ERROR;
}

/* prepare server cert verification by setting s->session->peer_chain from pkt */
MSG_PROCESS_RETURN tls_process_server_certificate_ntls(SSL *s, PACKET *pkt)
{
    unsigned long cert_list_len, cert_len;
    X509 *x = NULL;
    const unsigned char *certstart, *certbytes;
    unsigned int context = 0;

    if ((s->session->peer_chain = sk_X509_new_null()) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (context != 0
        || !PACKET_get_net_3(pkt, &cert_list_len)
        || PACKET_remaining(pkt) != cert_list_len
        || PACKET_remaining(pkt) == 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_net_3(pkt, &cert_len)
            || !PACKET_get_bytes(pkt, &certbytes, cert_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        certstart = certbytes;
        x = X509_new_ex(s->ctx->libctx, s->ctx->propq);
        if (x == NULL) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_MALLOC_FAILURE);
            ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (d2i_X509(&x, (const unsigned char **)&certbytes,
                     cert_len) == NULL) {
            SSLfatal_ntls(s, SSL_AD_BAD_CERTIFICATE, ERR_R_ASN1_LIB);
            goto err;
        }

        if (certbytes != (certstart + cert_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_CERT_LENGTH_MISMATCH);
            goto err;
        }

        if (!sk_X509_push(s->session->peer_chain, x)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x = NULL;
    }

# ifndef OPENSSL_NO_SM2
    {
        EVP_PKEY *pkey = NULL;
        int n = sk_X509_num(s->session->peer_chain) - 1;

        x = sk_X509_value(s->session->peer_chain, 0);
        pkey = X509_get0_pubkey(x);

        /* Print server signing certificate public key */
        if (pkey != NULL) {
            unsigned char *pubkey_buf = NULL;
            size_t pubkey_len = 0;
            pubkey_len = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_buf);
            if (pubkey_buf != NULL && pubkey_len > 0) {
                print_hex_data("客户端接收到的服务器签名证书公钥", pubkey_buf, pubkey_len);
                OPENSSL_free(pubkey_buf);
            }
        }

        /* Print server encryption certificate public key */
        if (sk_X509_num(s->session->peer_chain) > 1) {
            X509 *enc_x509 = sk_X509_value(s->session->peer_chain, 1);
            if (enc_x509 != NULL) {
                EVP_PKEY *enc_pkey = X509_get0_pubkey(enc_x509);
                if (enc_pkey != NULL) {
                    unsigned char *pubkey_buf = NULL;
                    size_t pubkey_len = 0;
                    pubkey_len = EVP_PKEY_get1_encoded_public_key(enc_pkey, &pubkey_buf);
                    if (pubkey_buf != NULL && pubkey_len > 0) {
                        print_hex_data("客户端接收到的服务器加密证书公钥", pubkey_buf, pubkey_len);
                        OPENSSL_free(pubkey_buf);
                    }
                }
            }
        }

        if (pkey != NULL && EVP_PKEY_is_sm2(pkey)) {
            if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            while (n >= 0) {
                X509 *cert = sk_X509_value(s->session->peer_chain, n);
                ASN1_OCTET_STRING *sm2_id;
                sm2_id = ASN1_OCTET_STRING_new();

                if (sm2_id == NULL) {
                    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                    goto err;
                }

                if (!ASN1_OCTET_STRING_set(sm2_id,
                                           (const unsigned char *)CERTVRIFY_SM2_ID,
                                           CERTVRIFY_SM2_ID_LEN)) {
                    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    ASN1_OCTET_STRING_free(sm2_id);
                    goto err;
                }

                X509_set0_sm2_id(cert, sm2_id);
                n--;
            }
        }
    }
# endif

    return MSG_PROCESS_CONTINUE_PROCESSING;

 err:
    X509_free(x);
    sk_X509_pop_free(s->session->peer_chain, X509_free);
    s->session->peer_chain = NULL;
    return MSG_PROCESS_ERROR;
}

/*
 * Verify the s->session->peer_chain and check server cert type.
 * On success set s->session->peer and s->session->verify_result.
 * Else the peer certificate verification callback may request retry.
 */
WORK_STATE tls_post_process_server_certificate_ntls(SSL *s, WORK_STATE wst)
{
    X509 *x = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *sk = s->session->peer_chain;
    const SSL_CERT_LOOKUP *clu;
    size_t certidx;
    int i, j;

    if (s->rwstate == SSL_RETRY_VERIFY)
        s->rwstate = SSL_NOTHING;

    if (sk_X509_num(sk) >= 2) {
        for (j = 0; j < 2; j++) {
            if (j == 0)
                sk_X509_push(sk, sk_X509_shift(sk));
            if (j == 1)
                sk_X509_unshift(sk, sk_X509_pop(sk));

            i = ssl_verify_cert_chain(s, sk);
            if (i > 0 && s->rwstate == SSL_RETRY_VERIFY) {
                return WORK_MORE_A;
            }

            /*
             * The documented interface is that SSL_VERIFY_PEER should be set in order
             * for client side verification of the server certificate to take place.
             * However, historically the code has only checked that *any* flag is set
             * to cause server verification to take place. Use of the other flags makes
             * no sense in client mode. An attempt to clean up the semantics was
             * reverted because at least one application *only* set
             * SSL_VERIFY_FAIL_IF_NO_PEER_CERT. Prior to the clean up this still caused
             * server verification to take place, after the clean up it silently did
             * nothing. SSL_CTX_set_verify()/SSL_set_verify() cannot validate the flags
             * sent to them because they are void functions. Therefore, we now use the
             * (less clean) historic behaviour of performing validation if any flag is
             * set. The *documented* interface remains the same.
             */
            if (s->verify_mode != SSL_VERIFY_NONE && i <= 0) {
                SSLfatal_ntls(s, ssl_x509err2alert_ntls(s->verify_result),
                              SSL_R_CERTIFICATE_VERIFY_FAILED);
                return WORK_ERROR;
            }
        }

        ERR_clear_error();          /* but we keep s->verify_result */

        /*
         * Inconsistency alert: cert_chain does include the peer's certificate,
         * which we don't include in statem_srvr.c
         */
        x = sk_X509_value(sk, 0);

        pkey = X509_get0_pubkey(x);

        if (pkey == NULL || EVP_PKEY_missing_parameters(pkey)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
            return WORK_ERROR;
        }

        if ((clu = ssl_cert_lookup_by_pkey(pkey, &certidx)) == NULL) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                          SSL_R_UNKNOWN_CERTIFICATE_TYPE);
            return WORK_ERROR;
        }

        /*
         * Check certificate type is consistent with ciphersuite. For TLS 1.3
         * skip check since TLS 1.3 ciphersuites can be used with any certificate
         * type.
         */
        if ((clu->amask & s->s3.tmp.new_cipher->algorithm_auth) == 0) {
            SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_WRONG_CERTIFICATE_TYPE);
            return WORK_ERROR;
        }

        ntls_log_peer_certs_verify_ok("Client", "服务端",
                                      sk_X509_value(sk, 0),
                                      sk_X509_value(sk, 1));
    } else {
        if (s->verify_mode != SSL_VERIFY_NONE) {
            SSLfatal_ntls(s, ssl_x509err2alert_ntls(s->verify_result),
                          SSL_R_CERTIFICATE_VERIFY_FAILED);
            return WORK_ERROR;
        }
    }

    if (x) {
        X509_free(s->session->peer);
        s->session->peer = x;
        X509_up_ref(x);
    }
    s->session->verify_result = s->verify_result;

    return WORK_FINISHED_CONTINUE;
}

static int tls_process_ske_ecckyber_ntls(SSL *s, PACKET *pkt)
{
    fprintf(stderr, "[NTLS Client] ========== 处理ServerKeyExchange (ECC+Kyber) ==========\n");
    fprintf(stderr, "[NTLS Client]   剩余数据长度: %zu 字节\n", PACKET_remaining(pkt));
    uint8_t *server_hybrid_pk = NULL;
    const unsigned char *kyber_pk_data = NULL;
    unsigned int kyber_pk_len = 0;
    X509 *enc_cert = NULL;
    EVP_PKEY *ecc_pkey = NULL;
    int ecc_pkey_owned = 0;
    EC_KEY *ec_key = NULL;
    const EC_POINT *ec_key_pk = NULL;
    const EC_GROUP *group = NULL;
    uint8_t *ecc_pk = NULL;

    fprintf(stderr, "[NTLS Client] 读取ServerPQKEMParams (Kyber公钥)...\n");
    if (!PACKET_get_net_2(pkt, &kyber_pk_len) || kyber_pk_len != KYBER_512_PK_SIZE) {
        fprintf(stderr, "[NTLS Client] 错误: Kyber公钥长度不匹配\n");
        fprintf(stderr, "[NTLS Client]   读取的长度: %u (期望: %d)\n", kyber_pk_len, KYBER_512_PK_SIZE);
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   读取的Kyber公钥长度: %u 字节\n", kyber_pk_len);
    if (!PACKET_get_bytes(pkt, &kyber_pk_data, kyber_pk_len)) {
        fprintf(stderr, "[NTLS Client] 错误: 无法读取Kyber公钥数据\n");
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   读取的Kyber公钥地址: %p\n", kyber_pk_data);
    print_hex_data("客户端接收到的Kyber公钥 (ServerPQKEMParams)", kyber_pk_data, kyber_pk_len);

    /* Get encryption certificate from server's certificate chain */
    /* The encryption certificate should be in the certificate chain */
    fprintf(stderr, "[NTLS Client] 从证书链获取加密证书...\n");
    enc_cert = sk_X509_value(s->session->peer_chain, 1);
    if (enc_cert == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 无法从证书链获取加密证书\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_MISSING_ENC_CERTIFICATE);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   加密证书地址: %p\n", enc_cert);

    /* Get ECC public key from encryption certificate */
    fprintf(stderr, "[NTLS Client] 从加密证书提取ECC公钥...\n");
    ecc_pkey = ossl_x509_hybrid_ntls_sm2_pubkey(s->ctx->libctx, s->ctx->propq,
                                                enc_cert);
    if (ecc_pkey == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 无法从证书获取SM2公钥\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    ecc_pkey_owned = 1;
    fprintf(stderr, "[NTLS Client]   ECC公钥(EVP_PKEY): %p\n", ecc_pkey);

    ec_key = EVP_PKEY_get1_EC_KEY(ecc_pkey);
    if (ec_key == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 无法从EVP_PKEY获取EC_KEY\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   EC_KEY: %p\n", ec_key);

    group = EC_KEY_get0_group(ec_key);
    ec_key_pk = EC_KEY_get0_public_key(ec_key);
    if (group == NULL || ec_key_pk == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 无法获取EC_GROUP或EC_POINT\n");
        EC_KEY_free(ec_key);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   EC_GROUP: %p, EC_POINT: %p\n", group, ec_key_pk);

    /* Allocate memory for ECC public key and hybrid public key */
    fprintf(stderr, "[NTLS Client] 分配内存...\n");
    ecc_pk = OPENSSL_malloc(ECC_PK_SIZE);
    server_hybrid_pk = OPENSSL_malloc(ECC_KYBER512_HYBRID_PK_SIZE);
    if (ecc_pk == NULL || server_hybrid_pk == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 内存分配失败\n");
        OPENSSL_free(ecc_pk);
        OPENSSL_free(server_hybrid_pk);
        EC_KEY_free(ec_key);
        if (ecc_pkey_owned)
            EVP_PKEY_free(ecc_pkey);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   ECC公钥缓冲区: %p (大小: %d)\n", ecc_pk, ECC_PK_SIZE);
    fprintf(stderr, "[NTLS Client]   混合公钥缓冲区: %p (大小: %d)\n", server_hybrid_pk, ECC_KYBER512_HYBRID_PK_SIZE);

    /* Encode ECC public key from certificate */
    fprintf(stderr, "[NTLS Client] 编码ECC公钥为未压缩格式...\n");
    if (EC_POINT_point2oct(group, ec_key_pk, POINT_CONVERSION_UNCOMPRESSED, 
                          ecc_pk, ECC_PK_SIZE, NULL) != ECC_PK_SIZE) {
        fprintf(stderr, "[NTLS Client] 错误: ECC公钥编码失败\n");
        OPENSSL_free(ecc_pk);
        OPENSSL_free(server_hybrid_pk);
        EC_KEY_free(ec_key);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    fprintf(stderr, "[NTLS Client]   ECC公钥编码成功\n");
    print_hex_data("客户端从证书提取的ECC公钥", ecc_pk, ECC_PK_SIZE);

    EC_KEY_free(ec_key);

    /* Construct hybrid public key: ECC from cert + Kyber from ServerPQKEMParams */
    fprintf(stderr, "[NTLS Client] 构造混合公钥...\n");
    fprintf(stderr, "[NTLS Client]   复制ECC公钥到 server_hybrid_pk[0:%d]\n", ECC_PK_SIZE);
    memcpy(server_hybrid_pk, ecc_pk, ECC_PK_SIZE);
    fprintf(stderr, "[NTLS Client]   复制Kyber公钥到 server_hybrid_pk[%d:%d]\n", ECC_PK_SIZE, ECC_PK_SIZE + KYBER_512_PK_SIZE);
    memcpy(server_hybrid_pk + ECC_PK_SIZE, kyber_pk_data, KYBER_512_PK_SIZE);
    fprintf(stderr, "[NTLS Client]   混合公钥构造完成\n");
    print_hex_data("客户端构造的服务器混合公钥 (ECC+Kyber)", server_hybrid_pk, ECC_KYBER512_HYBRID_PK_SIZE);

    OPENSSL_free(ecc_pk);
    if (ecc_pkey_owned)
        EVP_PKEY_free(ecc_pkey);

    fprintf(stderr, "[NTLS Client] 临时存储混合公钥到 s->s3.tmp.pms...\n");
    fprintf(stderr, "[NTLS Client]   原pms: %p, 原pmslen: %zu\n", s->s3.tmp.pms, s->s3.tmp.pmslen);
    OPENSSL_free(s->s3.tmp.pms);
    s->s3.tmp.pms = server_hybrid_pk;
    s->s3.tmp.pmslen = ECC_KYBER512_HYBRID_PK_SIZE;
    fprintf(stderr, "[NTLS Client]   新pms: %p, 新pmslen: %zu\n", s->s3.tmp.pms, s->s3.tmp.pmslen);

    /* Cache the agreed upon group in the SSL_SESSION */
    s->session->kex_group = 23; /* TLS_NAMED_GROUP_SECP256R1 */
    fprintf(stderr, "[NTLS Client]   设置的曲线ID: %d (TLS_NAMED_GROUP_SECP256R1)\n", s->session->kex_group);
    
    fprintf(stderr, "[NTLS Client] ========== ServerKeyExchange处理完成 ==========\n");
    return 1;
}

static int tls_process_ske_ecdhekyber_ntls(SSL *s, PACKET *pkt)
{
    PACKET encoded_pt;
    unsigned int curve_type, curve_id;
    const unsigned char *kyber_pk_data = NULL;
    unsigned int kyber_pk_len = 0;
    uint8_t *server_kyber_pk = NULL;
    int ret = 0;

    /* Read ServerECDHEParams */
    if (!PACKET_get_1(pkt, &curve_type) || !PACKET_get_net_2(pkt, &curve_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }

    if ((s->s3.peer_tmp =
            ssl_generate_param_group(s, curve_id)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (EVP_PKEY_set1_encoded_public_key(s->s3.peer_tmp,
                                         PACKET_data(&encoded_pt),
                                         PACKET_remaining(&encoded_pt)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_ECPOINT);
        return 0;
    }

    /* Cache the agreed upon group in the SSL_SESSION */
    s->session->kex_group = curve_id;

    /* Read ServerPQKEMParams: Kyber public key */
    if (!PACKET_get_net_2(pkt, &kyber_pk_len)
            || (kyber_pk_len != KYBER_768_PK_SIZE
                && kyber_pk_len != KYBER_512_PK_SIZE)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }
    if (!PACKET_get_bytes(pkt, &kyber_pk_data, kyber_pk_len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
        goto err;
    }
    print_hex_data("[NTLS Client] 接收到的Kyber公钥", kyber_pk_data, kyber_pk_len);

    /* Store Kyber public key for later use in ClientKeyExchange */
    server_kyber_pk = OPENSSL_malloc(kyber_pk_len);
    if (server_kyber_pk == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(server_kyber_pk, kyber_pk_data, kyber_pk_len);

    /* Store Kyber public key in pms field temporarily */
    OPENSSL_free(s->s3.tmp.pms);
    s->s3.tmp.pms = server_kyber_pk;
    s->s3.tmp.pmslen = kyber_pk_len;
    server_kyber_pk = NULL;  /* Don't free it here */

    ret = 1;
err:
    if (ret == 0) {
        OPENSSL_free(server_kyber_pk);
    }
    return ret;
}

static int tls_process_ske_sm2dhe_ntls(SSL *s, PACKET *pkt)
{
    PACKET encoded_pt;
    unsigned int curve_type, curve_id;

    if (!PACKET_get_1(pkt, &curve_type) || !PACKET_get_net_2(pkt, &curve_id)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
        return 0;
    }

    if ((s->s3.peer_tmp =
            ssl_generate_param_group(s, OSSL_TLS_GROUP_ID_sm2)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                      SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (EVP_PKEY_set1_encoded_public_key(s->s3.peer_tmp,
                                         PACKET_data(&encoded_pt),
                                         PACKET_remaining(&encoded_pt)) <= 0) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_ECPOINT);
        return 0;
    }

    /* Cache the agreed upon group in the SSL_SESSION */
    s->session->kex_group = curve_id;
    
    /* Print server's ephemeral public key for SM2DHE */
    print_kex_info_client_ske(s, SSL_kSM2DHE);
    
    return 1;
}

MSG_PROCESS_RETURN tls_process_key_exchange_ntls(SSL *s, PACKET *pkt)
{
    long alg_k;
    EVP_PKEY *pkey = NULL;
    int pkey_owned = 0;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    PACKET save_param_start, signature;
    unsigned char *buf = NULL;
    size_t buflen;

    alg_k = s->s3.tmp.new_cipher->algorithm_mkey;
    fprintf(stderr, "[NTLS Client] <<< Processing ServerKeyExchange, cipher: %s, alg_k: 0x%lx\n",
           s->s3.tmp.new_cipher ? SSL_CIPHER_get_name(s->s3.tmp.new_cipher) : "NULL",
           alg_k);

    save_param_start = *pkt;

    EVP_PKEY_free(s->s3.peer_tmp);
    s->s3.peer_tmp = NULL;
    EVP_PKEY_free(s->s3.tmp.aigis_kem_pkey);
    s->s3.tmp.aigis_kem_pkey = NULL;

    if (alg_k & SSL_kECCKyber) {
        if (!tls_process_ske_ecckyber_ntls(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    } else if (alg_k & SSL_kECDHEKyber) {
        if (!tls_process_ske_ecdhekyber_ntls(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    } else if (alg_k & SSL_kKyberAigisEnc) {
        unsigned int aigis_pk_len;
        const unsigned char *aigis_pk_data;
        EVP_PKEY_CTX *kgctx = NULL;
        EVP_PKEY *aigis_pub = NULL;
        unsigned char *mutable_pk = NULL;

        if (!PACKET_get_net_2(pkt, &aigis_pk_len)
            || PACKET_remaining(pkt) < aigis_pk_len) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
            goto err;
        }
        if (!PACKET_get_bytes(pkt, &aigis_pk_data, aigis_pk_len)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_TOO_SHORT);
            goto err;
        }
        mutable_pk = OPENSSL_memdup(aigis_pk_data, aigis_pk_len);
        kgctx = EVP_PKEY_CTX_new_from_name(s->ctx->libctx, "Aigis-Enc-2",
                                           s->ctx->propq);
        if (mutable_pk == NULL || kgctx == NULL) {
            OPENSSL_free(mutable_pk);
            EVP_PKEY_CTX_free(kgctx);
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        {
            OSSL_PARAM fromparams[] = {
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                  mutable_pk, aigis_pk_len),
                OSSL_PARAM_construct_end(),
            };
            if (EVP_PKEY_fromdata_init(kgctx) <= 0
                || EVP_PKEY_fromdata(kgctx, &aigis_pub, EVP_PKEY_PUBLIC_KEY,
                                     fromparams) <= 0
                || aigis_pub == NULL) {
                OPENSSL_free(mutable_pk);
                EVP_PKEY_CTX_free(kgctx);
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
                goto err;
            }
        }
        OPENSSL_free(mutable_pk);
        EVP_PKEY_CTX_free(kgctx);
        s->s3.tmp.aigis_kem_pkey = aigis_pub;
    } else if (alg_k & SSL_kKyber) {
        /* ServerKeyExchange has no KEX params; signed Dilithium over enc cert ASN.1 only */
    } else if (alg_k & SSL_kSM2DHE) {
        if (!tls_process_ske_sm2dhe_ntls(s, pkt)) {
            /* SSLfatal_ntls already called */
            goto err;
        }
    }

    /* get peer signing pkey for SKX verify */
    if (s->session->peer != NULL) {
        ossl_x509_ensure_pqc_providers(s->ctx->libctx);
        if (alg_k & (SSL_kECCKyber | SSL_kECDHEKyber)) {
            pkey = ossl_x509_hybrid_ntls_sm2_pubkey(s->ctx->libctx, s->ctx->propq,
                                                      s->session->peer);
            if (pkey != NULL)
                pkey_owned = 1;
        } else {
            pkey = ossl_x509_hybrid_ntls_pqc_pubkey(s->ctx->libctx, s->ctx->propq,
                                                    s->session->peer);
            if (pkey != NULL) {
                pkey_owned = 1;
            } else {
                const EVP_PKEY *peer_sign = X509_get0_pubkey(s->session->peer);

                if (peer_sign != NULL)
                    pkey = (EVP_PKEY *)peer_sign;
            }
        }
    }

    /* if it was signed, check the signature */
    if (pkey != NULL) {
        PACKET params;
        const EVP_MD *md = NULL;
        unsigned char *tbs;
        size_t tbslen;
        X509 *x509;
        int rv;

        if (alg_k & SSL_kECCKyber) {
            /* For ECC_Kyber, signature includes ASN.1Cert + ServerPQKEMParams */
            /* Get ServerPQKEMParams from save_param_start (before signature) */
            PACKET pq_kem_params;
            size_t pq_kem_params_len = PACKET_remaining(&save_param_start) - PACKET_remaining(pkt);
            if (!PACKET_get_sub_packet(&save_param_start, &pq_kem_params, pq_kem_params_len)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* get peer's encryption cert */
            x509 = sk_X509_value(s->session->peer_chain, 1);
            if (x509 == NULL
                || (buf = x509_to_asn1_ntls(x509, &buflen)) == NULL) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            /* Combine ASN.1Cert + ServerPQKEMParams */
            unsigned char *combined = OPENSSL_malloc(buflen + PACKET_remaining(&pq_kem_params));
            if (combined == NULL) {
                OPENSSL_free(buf);
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            memcpy(combined, buf, buflen);
            memcpy(combined + buflen, PACKET_data(&pq_kem_params), PACKET_remaining(&pq_kem_params));
            OPENSSL_free(buf);
            buf = combined;
            buflen = buflen + PACKET_remaining(&pq_kem_params);
            if (!PACKET_buf_init(&params, buf, buflen)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        } else if (alg_k & SSL_kECDHEKyber) {
            /*
             * For ECDHE_Kyber, signature includes ServerECDHEParams + ServerPQKEMParams
             * |pkt| now points to the beginning of the signature, so the difference
             * equals the length of the parameters.
             */
            if (!PACKET_get_sub_packet(&save_param_start, &params,
                                       PACKET_remaining(&save_param_start) -
                                       PACKET_remaining(pkt))) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else if (alg_k & SSL_kKyberAigisEnc) {
            if (!PACKET_get_sub_packet(&save_param_start, &params,
                                       PACKET_remaining(&save_param_start) -
                                       PACKET_remaining(pkt))) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else if (alg_k & SSL_kKyber) {
            x509 = sk_X509_value(s->session->peer_chain, 1);
            if (x509 == NULL
                || (buf = x509_to_asn1_ntls(x509, &buflen)) == NULL
                || !PACKET_buf_init(&params, buf, buflen)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        } else if (alg_k & SSL_kSM2DHE) {
		    /*
             * |pkt| now points to the beginning of the signature, so the difference
             * equals the length of the parameters.
             */
            if (!PACKET_get_sub_packet(&save_param_start, &params,
                                       PACKET_remaining(&save_param_start) -
                                       PACKET_remaining(pkt))) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else if (alg_k & (SSL_kSM2 | SSL_kRSA)) {
            /* get peer's encryption cert */
            x509 = sk_X509_value(s->session->peer_chain, 1);
            if (x509 == NULL
                || (buf = x509_to_asn1_ntls(x509, &buflen)) == NULL
                || !PACKET_buf_init(&params, buf, buflen)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        } else {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!tls1_set_peer_legacy_sigalg(s, pkey)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!tls1_lookup_md(s->ctx, s->s3.tmp.peer_sigalg, &md)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_R_NO_SUITABLE_DIGEST_ALGORITHM);
            goto err;
        }

        if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
            goto err;
        }

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_DigestVerifyInit_ex(md_ctx, &pctx,
                                    md == NULL ? NULL : EVP_MD_get0_name(md),
                                    s->ctx->libctx, s->ctx->propq, pkey,
                                    NULL) <= 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
            goto err;
        }

        if (EVP_PKEY_is_a(pkey, "SM2")) {
            if (EVP_PKEY_CTX_set1_id(pctx, SM2_DEFAULT_ID,
                                     SM2_DEFAULT_ID_LEN) <= 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
                goto err;
            }
        }

        tbslen = construct_key_exchange_tbs_ntls(s, &tbs, PACKET_data(&params),
                                                 PACKET_remaining(&params));
        if (tbslen == 0) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
        OPENSSL_free(buf);
        buf = NULL;

        rv = EVP_DigestVerify(md_ctx, PACKET_data(&signature),
                              PACKET_remaining(&signature), tbs, tbslen);
        OPENSSL_free(tbs);
        if (rv <= 0) {
            SSLfatal_ntls(s, SSL_AD_DECRYPT_ERROR, SSL_R_BAD_SIGNATURE);
            goto err;
        }
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
    } else {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_MISSING_SIGNING_CERT);
        goto err;
    }

    /* Print key exchange information after processing ServerKeyExchange */
    print_kex_info_client_ske(s, alg_k);

    if (pkey_owned)
        EVP_PKEY_free(pkey);

    return MSG_PROCESS_CONTINUE_READING;
 err:
    OPENSSL_free(buf);
    EVP_MD_CTX_free(md_ctx);
    if (pkey_owned)
        EVP_PKEY_free(pkey);
    return MSG_PROCESS_ERROR;
}

MSG_PROCESS_RETURN tls_process_certificate_request_ntls(SSL *s, PACKET *pkt)
{
    size_t i;

    /* Clear certificate validity flags */
    for (i = 0; i < SSL_PKEY_NUM; i++)
        s->s3.tmp.valid_flags[i] = 0;

    {
        PACKET ctypes;

        /* get the certificate types */
        if (!PACKET_get_length_prefixed_1(pkt, &ctypes)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
            return MSG_PROCESS_ERROR;
        }

        if (!PACKET_memdup(&ctypes, &s->s3.tmp.ctype, &s->s3.tmp.ctype_len)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        if (SSL_USE_SIGALGS(s)) {
            PACKET sigalgs;

            if (!PACKET_get_length_prefixed_2(pkt, &sigalgs)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
                return MSG_PROCESS_ERROR;
            }

            /*
             * Despite this being for certificates, preserve compatibility
             * with pre-TLS 1.3 and use the regular sigalgs field.
             */
            if (!tls1_save_sigalgs(s, &sigalgs, 0)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
				              SSL_R_SIGNATURE_ALGORITHMS_ERROR);
                return MSG_PROCESS_ERROR;
            }
            if (!tls1_process_sigalgs(s)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                return MSG_PROCESS_ERROR;
            }
        }

        /* get the CA RDNs */
        if (!parse_ca_names_ntls(s, pkt)) {
            /* SSLfatal_ntls() already called */
            return MSG_PROCESS_ERROR;
        }
    }

    if (PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    /* we should setup a certificate to return.... */
    s->s3.tmp.cert_req = 1;
    ntls_log_mutual_auth_request("Client");

    return MSG_PROCESS_CONTINUE_PROCESSING;
}

MSG_PROCESS_RETURN tls_process_new_session_ticket_ntls(SSL *s, PACKET *pkt)
{
    unsigned int ticklen;
    unsigned long ticket_lifetime_hint, age_add = 0;
    unsigned int sess_len;
    RAW_EXTENSION *exts = NULL;
    PACKET nonce;
    EVP_MD *sha256 = NULL;

    PACKET_null_init(&nonce);

    if (!PACKET_get_net_4(pkt, &ticket_lifetime_hint)
        || !PACKET_get_net_2(pkt, &ticklen)
        || (PACKET_remaining(pkt) != ticklen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    /*
     * Server is allowed to change its mind (in <=TLSv1.2) and send an empty
     * ticket. We already checked this TLSv1.3 case above, so it should never
     * be 0 here in that instance
     */
    if (ticklen == 0)
        return MSG_PROCESS_CONTINUE_READING;

    /*
     * Sessions must be immutable once they go into the session cache. Otherwise
     * we can get multi-thread problems. Therefore we don't "update" sessions,
     * we replace them with a duplicate. In TLSv1.3 we need to do this every
     * time a NewSessionTicket arrives because those messages arrive
     * post-handshake and the session may have already gone into the session
     * cache.
     */
    if (s->session->session_id_length > 0) {
        SSL_SESSION *new_sess;

        /*
         * We reused an existing session, so we need to replace it with a new
         * one
         */
        if ((new_sess = ssl_session_dup(s->session, 0)) == 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if ((s->session_ctx->session_cache_mode & SSL_SESS_CACHE_CLIENT) != 0) {
            /*
             * In TLSv1.2 and below the arrival of a new tickets signals that
             * any old ticket we were using is now out of date, so we remove the
             * old session from the cache. We carry on if this fails
             */
            SSL_CTX_remove_session(s->session_ctx, s->session);
        }

        SSL_SESSION_free(s->session);
        s->session = new_sess;
    }

    s->session->time = time(NULL);
    ssl_session_calculate_timeout(s->session);

    OPENSSL_free(s->session->ext.tick);
    s->session->ext.tick = NULL;
    s->session->ext.ticklen = 0;

    s->session->ext.tick = OPENSSL_malloc(ticklen);
    if (s->session->ext.tick == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, s->session->ext.tick, ticklen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        goto err;
    }

    s->session->ext.tick_lifetime_hint = ticket_lifetime_hint;
    s->session->ext.tick_age_add = age_add;
    s->session->ext.ticklen = ticklen;

    /*
     * There are two ways to detect a resumed ticket session. One is to set
     * an appropriate session ID and then the server must return a match in
     * ServerHello. This allows the normal client session ID matching to work
     * and we know much earlier that the ticket has been accepted. The
     * other way is to set zero length session ID when the ticket is
     * presented and rely on the handshake to determine session resumption.
     * We choose the former approach because this fits in with assumptions
     * elsewhere in OpenSSL. The session ID is set to the SHA256 hash of the
     * ticket.
     */
    sha256 = EVP_MD_fetch(s->ctx->libctx, "SHA2-256", s->ctx->propq);
    if (sha256 == NULL) {
        /* Error is already recorded */
        SSLfatal_alert_ntls(s, SSL_AD_INTERNAL_ERROR);
        goto err;
    }
    /*
     * We use sess_len here because EVP_Digest expects an int
     * but s->session->session_id_length is a size_t
     */
    if (!EVP_Digest(s->session->ext.tick, ticklen,
                    s->session->session_id, &sess_len,
                    sha256, NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_MD_free(sha256);
    sha256 = NULL;
    s->session->session_id_length = sess_len;
    s->session->not_resumable = 0;

    return MSG_PROCESS_CONTINUE_READING;
 err:
    EVP_MD_free(sha256);
    OPENSSL_free(exts);
    return MSG_PROCESS_ERROR;
}

/*
 * In TLSv1.3 this is called from the extensions code, otherwise it is used to
 * parse a separate message. Returns 1 on success or 0 on failure
 */
int tls_process_cert_status_body_ntls(SSL *s, PACKET *pkt)
{
    size_t resplen;
    unsigned int type;

    if (!PACKET_get_1(pkt, &type)
        || type != TLSEXT_STATUSTYPE_ocsp) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_UNSUPPORTED_STATUS_TYPE);
        return 0;
    }
    if (!PACKET_get_net_3_len(pkt, &resplen)
        || PACKET_remaining(pkt) != resplen) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return 0;
    }
    s->ext.ocsp.resp = OPENSSL_malloc(resplen);
    if (s->ext.ocsp.resp == NULL) {
        s->ext.ocsp.resp_len = 0;
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    s->ext.ocsp.resp_len = resplen;
    if (!PACKET_copy_bytes(pkt, s->ext.ocsp.resp, resplen)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    return 1;
}


MSG_PROCESS_RETURN tls_process_cert_status_ntls(SSL *s, PACKET *pkt)
{
    if (!tls_process_cert_status_body_ntls(s, pkt)) {
        /* SSLfatal_ntls() already called */
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

/*
 * Perform miscellaneous checks and processing after we have received the
 * server's initial flight. In TLS1.3 this is after the Server Finished message.
 * In <=TLS1.2 this is after the ServerDone message. Returns 1 on success or 0
 * on failure.
 */
int tls_process_initial_server_flight_ntls(SSL *s)
{
    /*
     * at this point we check that we have the required stuff from
     * the server
     */
    if (!ssl3_check_cert_and_algorithm_ntls(s)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    /*
     * Call the ocsp status callback if needed. The |ext.ocsp.resp| and
     * |ext.ocsp.resp_len| values will be set if we actually received a status
     * message, or NULL and -1 otherwise
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_nothing
            && s->ctx->ext.status_cb != NULL) {
        int ret = s->ctx->ext.status_cb(s, s->ctx->ext.status_arg);

        if (ret == 0) {
            SSLfatal_ntls(s, SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
                          SSL_R_INVALID_STATUS_RESPONSE);
            return 0;
        }
        if (ret < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR,
                          SSL_R_OCSP_CALLBACK_FAILURE);
            return 0;
        }
    }
#ifndef OPENSSL_NO_CT
    if (s->ct_validation_callback != NULL) {
        /* Note we validate the SCTs whether or not we abort on error */
        if (!ssl_validate_ct(s) && (s->verify_mode & SSL_VERIFY_PEER)) {
            /* SSLfatal_ntls() already called */
            return 0;
        }
    }
#endif

    return 1;
}

MSG_PROCESS_RETURN tls_process_server_done_ntls(SSL *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) > 0) {
        /* should contain no data */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (!tls_process_initial_server_flight_ntls(s)) {
        /* SSLfatal_ntls() already called */
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_FINISHED_READING;
}

/* construct encrypted pre master secret for kRSA or kSM2 */
static int tls_construct_cke_pms_ntls(SSL *s, WPACKET *pkt, unsigned long alg_k)
{
    unsigned char *encbytes1, *encbytes2;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t enclen;
    unsigned char *pms = NULL;
    size_t pmslen = 0;
    X509 *x509;

    /*
     * for client side, s->session->peer == s->session->peer_chain[0] is
     * the server signing certificate.
     *
     * s->session->peer_chain[1] is the server encryption certificate
     */
    if (s->session->peer_chain == NULL
            || (x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = X509_get0_pubkey(x509);
    if (((alg_k & SSL_kRSA) && !EVP_PKEY_is_a(pkey, "RSA"))
            || ((alg_k & SSL_kSM2) && !EVP_PKEY_is_a(pkey, "SM2"))) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pmslen = SSL_MAX_MASTER_KEY_LENGTH;
    pms = OPENSSL_malloc(pmslen);
    if (pms == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    pms[0] = s->client_version >> 8;
    pms[1] = s->client_version & 0xff;
    if (RAND_bytes_ex(s->ctx->libctx, pms + 2, pmslen - 2, 0) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Print premaster secret before encryption */
    if (alg_k & SSL_kSM2) {
        print_hex_data("客户端生成的预主密钥 (SM2)", pms, pmslen);
    } else if (alg_k & SSL_kRSA) {
        print_hex_data("客户端生成的预主密钥 (RSA)", pms, pmslen);
    }

    /* Print server encryption certificate public key */
    if (pkey != NULL) {
        unsigned char *pubkey_buf = NULL;
        size_t pubkey_len = 0;
        pubkey_len = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_buf);
        if (pubkey_buf != NULL && pubkey_len > 0) {
            if (alg_k & SSL_kSM2) {
                print_hex_data("客户端使用的服务器加密证书公钥 (SM2)", pubkey_buf, pubkey_len);
            } else if (alg_k & SSL_kRSA) {
                print_hex_data("客户端使用的服务器加密证书公钥 (RSA)", pubkey_buf, pubkey_len);
            }
            OPENSSL_free(pubkey_buf);
        }
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(s->ctx->libctx, pkey, s->ctx->propq);
    if (pctx == NULL || EVP_PKEY_encrypt_init(pctx) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }

    if ((alg_k & SSL_kRSA)
            && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0
            || !WPACKET_sub_reserve_bytes_u16(pkt, enclen, &encbytes1)
            || EVP_PKEY_encrypt(pctx, encbytes1, &enclen, pms, pmslen) <= 0
            || !WPACKET_sub_allocate_bytes_u16(pkt, enclen, &encbytes2)
            || encbytes1 != encbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_RSA_ENCRYPT);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    /* Log the premaster secret, if logging is enabled. */
    if ((alg_k & SSL_kRSA)
        && !ssl_log_rsa_client_key_exchange(s, encbytes1, enclen, pms, pmslen))
    {
        /* SSLfatal() already called */
        goto err;
    }

    s->s3.tmp.pms = pms;
    s->s3.tmp.pmslen = pmslen;

    return 1;
 err:
    OPENSSL_clear_free(pms, pmslen);
    EVP_PKEY_CTX_free(pctx);

    return 0;
}

static int tls_construct_cke_ecckyber_ntls(SSL *s, WPACKET *pkt)
{
    fprintf(stderr, "[NTLS Client] ========== 构造ClientKeyExchange (ECC+Kyber) ==========\n");
    uint8_t *server_hybrid_pk = NULL;
    uint8_t *kyber_ct = NULL;
    uint8_t *kyber_ss = NULL;
    unsigned char *pms = NULL;
    size_t pmslen = 0;
    unsigned char *encbytes1, *encbytes2;
    size_t enclen;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x509 = NULL;
    uint8_t *hybrid_ss = NULL;
    OSSL_LIB_CTX *libctx = s->ctx->libctx;
    int ret = 0;

    /* Get server's hybrid public key (stored in pms field) */
    fprintf(stderr, "[NTLS Client] 获取服务器混合公钥...\n");
    server_hybrid_pk = s->s3.tmp.pms;
    fprintf(stderr, "[NTLS Client]   s->s3.tmp.pms: %p, s->s3.tmp.pmslen: %zu\n", server_hybrid_pk, s->s3.tmp.pmslen);
    if (server_hybrid_pk == NULL || s->s3.tmp.pmslen != ECC_KYBER512_HYBRID_PK_SIZE) {
        fprintf(stderr, "[NTLS Client] 错误: 服务器混合公钥未正确存储\n");
        fprintf(stderr, "[NTLS Client]   server_hybrid_pk: %p (期望: 非NULL)\n", server_hybrid_pk);
        fprintf(stderr, "[NTLS Client]   pmslen: %zu (期望: %d)\n", s->s3.tmp.pmslen, ECC_KYBER512_HYBRID_PK_SIZE);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fprintf(stderr, "[NTLS Client]   服务器混合公钥获取成功\n");

    /* Get server encryption certificate for PMS encryption */
    fprintf(stderr, "[NTLS Client] 获取服务器加密证书...\n");
    if (s->session->peer_chain == NULL
            || (x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    pkey = ossl_x509_hybrid_ntls_sm2_pubkey(s->ctx->libctx, s->ctx->propq, x509);
    if (pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fprintf(stderr, "[NTLS Client]   服务器加密证书SM2公钥获取成功\n");

    /* Generate pre-master secret (PMS) */
    fprintf(stderr, "[NTLS Client] 生成预主密钥 (PMS)...\n");
    pmslen = SSL_MAX_MASTER_KEY_LENGTH;
    pms = OPENSSL_malloc(pmslen);
    if (pms == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pms[0] = s->client_version >> 8;
    pms[1] = s->client_version & 0xff;
    if (RAND_bytes_ex(s->ctx->libctx, pms + 2, pmslen - 2, 0) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    print_hex_data("客户端生成的预主密钥 (ECC)", pms, pmslen);

    /* Encrypt PMS with server encryption certificate public key */
    fprintf(stderr, "[NTLS Client] 使用服务器加密证书公钥加密PMS...\n");
    pctx = EVP_PKEY_CTX_new_from_pkey(s->ctx->libctx, pkey, s->ctx->propq);
    if (pctx == NULL || EVP_PKEY_encrypt_init(pctx) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &enclen, pms, pmslen) <= 0
            || !WPACKET_sub_reserve_bytes_u16(pkt, enclen, &encbytes1)
            || EVP_PKEY_encrypt(pctx, encbytes1, &enclen, pms, pmslen) <= 0
            || !WPACKET_sub_allocate_bytes_u16(pkt, enclen, &encbytes2)
            || encbytes1 != encbytes2) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_BAD_RSA_ENCRYPT);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    fprintf(stderr, "[NTLS Client]   PMS加密成功，密文长度: %zu 字节\n", enclen);

    /* Allocate memory for Kyber ciphertext and shared secret */
    fprintf(stderr, "[NTLS Client] 分配Kyber相关内存...\n");
    kyber_ct = OPENSSL_malloc(ECC_KYBER512_HYBRID_CT_SIZE);
    kyber_ss = OPENSSL_malloc(KYBER_512_SS_SIZE);
    if (kyber_ct == NULL || kyber_ss == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: 内存分配失败\n");
        OPENSSL_free(kyber_ct);
        OPENSSL_free(kyber_ss);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    fprintf(stderr, "[NTLS Client]   Kyber密文缓冲区: %p (大小: %d)\n", kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE);
    fprintf(stderr, "[NTLS Client]   Kyber共享秘密缓冲区: %p (大小: %d)\n", kyber_ss, KYBER_512_SS_SIZE);

    /* Perform Kyber encapsulation */
    fprintf(stderr, "[NTLS Client] 开始执行Kyber封装...\n");
    fprintf(stderr, "[NTLS Client]   使用的Kyber公钥地址: server_hybrid_pk + %d = %p\n", ECC_PK_SIZE, server_hybrid_pk + ECC_PK_SIZE);
    if (ecc_kyber512_hybrid_encaps(libctx, kyber_ss, KYBER_512_SS_SIZE,
                                   kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE,
                                   server_hybrid_pk, ECC_KYBER512_HYBRID_PK_SIZE) == 0) {
        fprintf(stderr, "[NTLS Client] 错误: Kyber封装失败\n");
        OPENSSL_clear_free(kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE);
        OPENSSL_clear_free(kyber_ss, KYBER_512_SS_SIZE);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fprintf(stderr, "[NTLS Client] Kyber封装成功\n");
    print_hex_data("客户端封装生成的Kyber密文", kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE);
    print_hex_data("客户端封装得到的Kyber共享秘密", kyber_ss, KYBER_512_SS_SIZE);

    /* Send Kyber ciphertext */
    fprintf(stderr, "[NTLS Client] 发送Kyber密文...\n");
    fprintf(stderr, "[NTLS Client]   格式: [2字节长度][Kyber密文(%d字节)]\n", ECC_KYBER512_HYBRID_CT_SIZE);
    if (!WPACKET_put_bytes_u16(pkt, ECC_KYBER512_HYBRID_CT_SIZE)
            || !WPACKET_memcpy(pkt, kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE)) {
        fprintf(stderr, "[NTLS Client] 错误: 写入Kyber密文失败\n");
        OPENSSL_clear_free(kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE);
        OPENSSL_clear_free(kyber_ss, KYBER_512_SS_SIZE);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    fprintf(stderr, "[NTLS Client]   Kyber密文已成功写入\n");

    /* Combine PMS and Kyber shared secret as hybrid secret (80 bytes) */
    fprintf(stderr, "[NTLS Client] 组合混合共享秘密 (PMS + Kyber_SS)...\n");
    hybrid_ss = OPENSSL_malloc(ECC_KYBER512_HYBRID_SS_SIZE);
    if (hybrid_ss == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    /* Use full PMS (48 bytes) + Kyber_SS (32 bytes) = 80 bytes */
    memcpy(hybrid_ss, pms, pmslen);  /* Copy full PMS (48 bytes) */
    memcpy(hybrid_ss + pmslen, kyber_ss, KYBER_512_SS_SIZE);  /* Append Kyber_SS (32 bytes) */
    print_hex_data("客户端组合的混合共享秘密 (ECC_PMS + Kyber_SS)", hybrid_ss, ECC_KYBER512_HYBRID_SS_SIZE);

    /* Store hybrid shared secret for master secret generation (64 bytes) */
    fprintf(stderr, "[NTLS Client] 临时存储混合共享秘密到 s->s3.tmp.pms...\n");
    fprintf(stderr, "[NTLS Client]   原pms: %p, 原pmslen: %zu\n", s->s3.tmp.pms, s->s3.tmp.pmslen);
    OPENSSL_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    s->s3.tmp.pms = hybrid_ss;
    s->s3.tmp.pmslen = ECC_KYBER512_HYBRID_SS_SIZE;
    fprintf(stderr, "[NTLS Client]   新pms: %p, 新pmslen: %zu\n", s->s3.tmp.pms, s->s3.tmp.pmslen);
    hybrid_ss = NULL;  /* Don't free it here, it's now in s->s3.tmp.pms */

    OPENSSL_clear_free(pms, pmslen);
    pms = NULL;
    OPENSSL_free(kyber_ct);  /* kyber_ct is no longer needed after WPACKET_memcpy */
    kyber_ct = NULL;
    OPENSSL_clear_free(kyber_ss, KYBER_512_SS_SIZE);
    kyber_ss = NULL;
    ret = 1;
    fprintf(stderr, "[NTLS Client] ========== ClientKeyExchange构造完成 ==========\n");

err:
    if (ret == 0)
        fprintf(stderr, "[NTLS Client] ========== ClientKeyExchange构造失败 ==========\n");
    if (pms != NULL)
        OPENSSL_clear_free(pms, pmslen);
    if (kyber_ct != NULL)
        OPENSSL_clear_free(kyber_ct, ECC_KYBER512_HYBRID_CT_SIZE);
    if (kyber_ss != NULL)
        OPENSSL_clear_free(kyber_ss, KYBER_512_SS_SIZE);
    if (hybrid_ss != NULL)
        OPENSSL_clear_free(hybrid_ss, ECC_KYBER512_HYBRID_SS_SIZE);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static int tls_construct_cke_ecdhekyber_ntls(SSL *s, WPACKET *pkt)
{
    unsigned char *encodedPoint = NULL;
    size_t encoded_pt_len = 0;
    EVP_PKEY *ckey = NULL, *skey = NULL;
    EVP_PKEY *skey_ec = NULL;
    uint8_t *server_kyber_pk = NULL;
    uint8_t *server_kyber_pk_copy = NULL;
    uint8_t *hybrid_pk_tmp = NULL;
    uint8_t *kyber_ct = NULL;
    uint8_t *kyber_ss = NULL;
    uint8_t *combined_ss = NULL;
    unsigned char *server_enc_cert_ec_pub = NULL;
    size_t server_enc_cert_ec_pub_len = 0;
    X509 *server_enc_x509 = NULL;
    EVP_PKEY *server_enc_pkey = NULL;
    size_t combined_ss_len = 0;
    size_t kyber_pk_size = 0;
    size_t kyber_ct_size = 0;
    size_t kyber_ss_size = KYBER_768_SS_SIZE;
    size_t hybrid_pk_size = ECC_KYBER_HYBRID_PK_SIZE;
    unsigned char *ecdhe_ss = NULL;
    size_t ecdhe_ss_len = 0;
    unsigned char *server_ec_pt = NULL;
    size_t server_ec_pt_len = 0;
    int ret = 0;
    int curve_id;
    OSSL_LIB_CTX *libctx = s->ctx->libctx;

    skey = s->s3.peer_tmp;  /* Server's ECDHE public key */
    if (skey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Get server's Kyber public key (stored in pms field from ServerKeyExchange) */
    server_kyber_pk = s->s3.tmp.pms;
    kyber_pk_size = s->s3.tmp.pmslen;
    if (server_kyber_pk == NULL
            || (kyber_pk_size != KYBER_768_PK_SIZE
                && kyber_pk_size != KYBER_512_PK_SIZE)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (kyber_pk_size == KYBER_512_PK_SIZE) {
        kyber_ct_size = ECC_KYBER512_HYBRID_CT_SIZE;
        kyber_ss_size = KYBER_512_SS_SIZE;
        hybrid_pk_size = ECC_KYBER512_HYBRID_PK_SIZE;
    } else {
        kyber_ct_size = KYBER_768_CT_SIZE;
        kyber_ss_size = KYBER_768_SS_SIZE;
        hybrid_pk_size = ECC_KYBER_HYBRID_PK_SIZE;
    }

    /*
     * ssl_derive_ntls() will overwrite s->s3.tmp.pms with the ECDHE shared
     * secret, so we must copy Kyber public key out first.
     */
    server_kyber_pk_copy = OPENSSL_malloc(kyber_pk_size);
    if (server_kyber_pk_copy == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(server_kyber_pk_copy, server_kyber_pk, kyber_pk_size);
    print_hex_data("[NTLS Client] 封装前使用的Kyber公钥", server_kyber_pk_copy, kyber_pk_size);

    /* Generate client's ECDHE key pair by named group (same style as server) */
    curve_id = tls1_shared_group(s, -2);
    if (curve_id == 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
                      SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
        goto err;
    }
    ckey = ssl_generate_pkey_group(s, curve_id);
    if (ckey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    fprintf(stderr, "[NTLS Client]   ECDHE客户端密钥生成完成，curve_id=%d\n", curve_id);

    /*
     * Rebuild server ephemeral key as EC type for ECDH derive compatibility.
     * The key parsed from SKE may be SM2-typed on this branch.
     */
    server_ec_pt_len = EVP_PKEY_get1_encoded_public_key(skey, &server_ec_pt);
    if (server_ec_pt_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EC_LIB);
        goto err;
    }
    skey_ec = EVP_PKEY_new();
    if (skey_ec == NULL || EVP_PKEY_copy_parameters(skey_ec, ckey) <= 0
            || EVP_PKEY_set1_encoded_public_key(skey_ec, server_ec_pt, server_ec_pt_len) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_COPY_PARAMETERS_FAILED);
        goto err;
    }

    /* Derive ECDHE shared secret (32 bytes) */
    if (ssl_derive_ntls(s, ckey, skey_ec, 0) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /* Get ECDHE shared secret */
    ecdhe_ss = s->s3.tmp.pms;
    ecdhe_ss_len = s->s3.tmp.pmslen;
    fprintf(stderr, "[NTLS Client]   ECDHE共享秘密长度: %zu (期望: ~%d)\n", ecdhe_ss_len, ECC_SS_SIZE);
    if (ecdhe_ss == NULL || ecdhe_ss_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Generate encoding of client's ECDHE public key */
    encoded_pt_len = EVP_PKEY_get1_encoded_public_key(ckey, &encodedPoint);
    if (encoded_pt_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EC_LIB);
        goto err;
    }

    /* Send client's ECDHE public key */
    if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE)
            || !WPACKET_put_bytes_u16(pkt, curve_id)
            || !WPACKET_sub_memcpy_u8(pkt, encodedPoint, encoded_pt_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Allocate memory for Kyber ciphertext and shared secret */
    kyber_ct = OPENSSL_malloc(kyber_ct_size);
    kyber_ss = OPENSSL_malloc(kyber_ss_size);
    if (kyber_ct == NULL || kyber_ss == NULL) {
        OPENSSL_free(kyber_ct);
        OPENSSL_free(kyber_ss);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    hybrid_pk_tmp = OPENSSL_malloc(hybrid_pk_size);
    if (hybrid_pk_tmp == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: hybrid_pk_tmp 分配失败\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (s->session->peer_chain == NULL
            || (server_enc_x509 = sk_X509_value(s->session->peer_chain, 1)) == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    server_enc_pkey = ossl_x509_hybrid_ntls_sm2_pubkey(s->ctx->libctx, s->ctx->propq,
                                                       server_enc_x509);
    if (server_enc_pkey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    server_enc_cert_ec_pub_len =
        EVP_PKEY_get1_encoded_public_key(server_enc_pkey, &server_enc_cert_ec_pub);
    EVP_PKEY_free(server_enc_pkey);
    server_enc_pkey = NULL;
    if (server_enc_cert_ec_pub_len != ECC_PK_SIZE) {
        fprintf(stderr, "[NTLS Client] 错误: 服务器加密证书ECC公钥长度异常: %zu (期望=%d)\n",
                server_enc_cert_ec_pub_len, ECC_PK_SIZE);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(hybrid_pk_tmp, server_enc_cert_ec_pub, ECC_PK_SIZE);
    memcpy(hybrid_pk_tmp + ECC_PK_SIZE, server_kyber_pk_copy, kyber_pk_size);

    if (kyber_pk_size == KYBER_512_PK_SIZE) {
        if (ecc_kyber512_hybrid_encaps(libctx,
                                       kyber_ss, kyber_ss_size,
                                       kyber_ct, kyber_ct_size,
                                       hybrid_pk_tmp, hybrid_pk_size) == 0) {
            fprintf(stderr, "[NTLS Client] 错误: ML-KEM-512 encaps 失败\n");
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else if (ecc_kyber_hybrid_encaps(libctx,
                                       kyber_ss, kyber_ss_size,
                                       kyber_ct, kyber_ct_size,
                                       hybrid_pk_tmp, hybrid_pk_size) == 0) {
        fprintf(stderr, "[NTLS Client] 错误: Kyber encaps 失败\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_clear_free(hybrid_pk_tmp, hybrid_pk_size);
    hybrid_pk_tmp = NULL;

    /* Send Kyber ciphertext */
    if (!WPACKET_put_bytes_u16(pkt, kyber_ct_size)
            || !WPACKET_memcpy(pkt, kyber_ct, kyber_ct_size)) {
        fprintf(stderr, "[NTLS Client] 错误: 写入Kyber密文失败\n");
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Combine ECDHE shared secret (variable, commonly 32/48) + Kyber shared secret (32 bytes) */
    combined_ss_len = ecdhe_ss_len + kyber_ss_size;
    combined_ss = OPENSSL_malloc(combined_ss_len);
    if (combined_ss == NULL) {
        fprintf(stderr, "[NTLS Client] 错误: combined_ss 分配失败, len=%zu\n", combined_ss_len);
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(combined_ss, ecdhe_ss, ecdhe_ss_len);
    memcpy(combined_ss + ecdhe_ss_len, kyber_ss, kyber_ss_size);
    fprintf(stderr, "[NTLS Client]   组合共享秘密长度: %zu (ECDHE=%zu + Kyber=%zu)\n",
            combined_ss_len, ecdhe_ss_len, kyber_ss_size);

    /* Store combined shared secret */
    OPENSSL_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    s->s3.tmp.pms = combined_ss;
    s->s3.tmp.pmslen = combined_ss_len;
    combined_ss = NULL;  /* Don't free it here */
    combined_ss_len = 0;

    OPENSSL_clear_free(kyber_ct, kyber_ct_size);
    kyber_ct = NULL;
    OPENSSL_clear_free(kyber_ss, kyber_ss_size);
    kyber_ss = NULL;

    ret = 1;
 err:
    OPENSSL_free(encodedPoint);
    OPENSSL_free(server_enc_cert_ec_pub);
    OPENSSL_free(server_ec_pt);
    EVP_PKEY_free(ckey);
    EVP_PKEY_free(skey_ec);
    if (hybrid_pk_tmp != NULL)
        OPENSSL_clear_free(hybrid_pk_tmp, hybrid_pk_size);
    if (server_kyber_pk_copy != NULL)
        OPENSSL_clear_free(server_kyber_pk_copy, kyber_pk_size);
    OPENSSL_clear_free(kyber_ct, kyber_ct_size);
    OPENSSL_clear_free(kyber_ss, kyber_ss_size);
    if (combined_ss != NULL && combined_ss_len > 0)
        OPENSSL_clear_free(combined_ss, combined_ss_len);
    return ret;
}

static int tls_construct_cke_sm2dhe_ntls(SSL *s, WPACKET *pkt)
{
    unsigned char *encodedPoint = NULL;
    size_t encoded_pt_len = 0;
    EVP_PKEY *ckey = NULL, *skey = NULL;
    int ret = 0;
    int curve_id;

    skey = s->s3.peer_tmp;
    if (skey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ckey = ssl_generate_pkey(s, skey);
    if (ckey == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (ssl_derive_ntls(s, ckey, skey, 0) == 0) {
        /* SSLfatal_ntls() already called */
        goto err;
    }

    /* Generate encoding of client key */
    encoded_pt_len = EVP_PKEY_get1_encoded_public_key(ckey, &encodedPoint);
    if (encoded_pt_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EC_LIB);
        goto err;
    }

    curve_id = tls1_shared_group(s, -2);

    if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_put_bytes_u8(pkt, curve_id)
            || !WPACKET_sub_memcpy_u8(pkt, encodedPoint, encoded_pt_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ret = 1;
 err:
    OPENSSL_free(encodedPoint);
    EVP_PKEY_free(ckey);
    return ret;
}

static int tls_construct_cke_kyber_aigis_enc_dilithium_ntls(SSL *s, WPACKET *pkt)
{
    X509 *enc_cert;
    EVP_PKEY *enc_pub;
    EVP_PKEY *aigis_pub;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ct_k = NULL;
    unsigned char *ct_a = NULL;
    unsigned char *ss_k = NULL;
    unsigned char *ss_a = NULL;
    unsigned char *combined = NULL;
    size_t ct_k_len = 0, ct_a_len = 0;
    size_t ss_k_len = 0, ss_a_len = 0;
    size_t combined_len = 0;
    int ret = 0;

    enc_cert = sk_X509_value(s->session->peer_chain, 1);
    if (enc_cert == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_MISSING_ENC_CERTIFICATE);
        return 0;
    }
    enc_pub = X509_get0_pubkey(enc_cert);
    aigis_pub = s->s3.tmp.aigis_kem_pkey;
    if (enc_pub == NULL || aigis_pub == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(s->ctx->libctx, enc_pub, s->ctx->propq);
    if (pctx == NULL
            || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_encapsulate(pctx, NULL, &ct_k_len, NULL, &ss_k_len) <= 0
            || ct_k_len == 0 || ss_k_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    ct_k = OPENSSL_malloc(ct_k_len);
    ss_k = OPENSSL_malloc(ss_k_len);
    if (ct_k == NULL || ss_k == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_encapsulate(pctx, ct_k, &ct_k_len, ss_k, &ss_k_len) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    pctx = EVP_PKEY_CTX_new_from_pkey(s->ctx->libctx, aigis_pub, s->ctx->propq);
    if (pctx == NULL
            || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_encapsulate(pctx, NULL, &ct_a_len, NULL, &ss_a_len) <= 0
            || ct_a_len == 0 || ss_a_len == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    ct_a = OPENSSL_malloc(ct_a_len);
    ss_a = OPENSSL_malloc(ss_a_len);
    if (ct_a == NULL || ss_a == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_encapsulate(pctx, ct_a, &ct_a_len, ss_a, &ss_a_len) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    combined_len = ss_k_len + ss_a_len;
    combined = OPENSSL_malloc(combined_len);
    if (combined == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(combined, ss_k, ss_k_len);
    memcpy(combined + ss_k_len, ss_a, ss_a_len);
    OPENSSL_clear_free(ss_k, ss_k_len);
    ss_k = NULL;
    OPENSSL_clear_free(ss_a, ss_a_len);
    ss_a = NULL;

    if (!WPACKET_put_bytes_u16(pkt, (unsigned int)ct_k_len)
            || !WPACKET_memcpy(pkt, ct_k, ct_k_len)
            || !WPACKET_put_bytes_u16(pkt, (unsigned int)ct_a_len)
            || !WPACKET_memcpy(pkt, ct_a, ct_a_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    s->s3.tmp.pms = combined;
    s->s3.tmp.pmslen = combined_len;
    combined = NULL;
    ret = 1;
 err:
    OPENSSL_free(ct_k);
    OPENSSL_free(ct_a);
    OPENSSL_clear_free(ss_k, ss_k_len);
    OPENSSL_clear_free(ss_a, ss_a_len);
    OPENSSL_clear_free(combined, combined_len);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int tls_construct_cke_kyber_dilithium_ntls(SSL *s, WPACKET *pkt)
{
    X509 *enc_cert;
    EVP_PKEY *enc_pub = NULL;
    const EVP_PKEY *cert_pub;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ct = NULL;
    unsigned char *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    int ret = 0;
    int owned = 0;

    enc_cert = sk_X509_value(s->session->peer_chain, 1);
    if (enc_cert == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_MISSING_ENC_CERTIFICATE);
        return 0;
    }
    enc_pub = ossl_x509_hybrid_ntls_pqc_pubkey(s->ctx->libctx, s->ctx->propq,
                                               enc_cert);
    if (enc_pub != NULL) {
        owned = 1;
    } else {
        enc_pub = (EVP_PKEY *)X509_get0_pubkey(enc_cert);
        if (enc_pub == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    cert_pub = enc_pub;

    pctx = EVP_PKEY_CTX_new_from_pkey(s->ctx->libctx, cert_pub, s->ctx->propq);
    if (pctx == NULL
            || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_encapsulate(pctx, NULL, &ctlen, NULL, &sslen) <= 0
            || ctlen == 0 || sslen == 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    ct = OPENSSL_malloc(ctlen);
    ss = OPENSSL_malloc(sslen);
    if (ct == NULL || ss == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_encapsulate(pctx, ct, &ctlen, ss, &sslen) <= 0) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_EVP_LIB);
        goto err;
    }
    if (!WPACKET_put_bytes_u16(pkt, (unsigned int)ctlen)
            || !WPACKET_memcpy(pkt, ct, ctlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    s->s3.tmp.pms = ss;
    s->s3.tmp.pmslen = sslen;
    ss = NULL;
    ret = 1;
 err:
    OPENSSL_free(ct);
    OPENSSL_clear_free(ss, sslen);
    EVP_PKEY_CTX_free(pctx);
    if (owned)
        EVP_PKEY_free(enc_pub);
    return ret;
}

int tls_construct_client_key_exchange_ntls(SSL *s, WPACKET *pkt)
{
    unsigned long alg_k;

    alg_k = s->s3.tmp.new_cipher->algorithm_mkey;
    fprintf(stderr, "[NTLS Client] >>> Constructing ClientKeyExchange, cipher: %s, alg_k: 0x%lx\n",
           s->s3.tmp.new_cipher ? SSL_CIPHER_get_name(s->s3.tmp.new_cipher) : "NULL",
           alg_k);

    if (alg_k & (SSL_kRSA | SSL_kSM2)) {
        if (!tls_construct_cke_pms_ntls(s, pkt, alg_k)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kECCKyber) {
        if (!tls_construct_cke_ecckyber_ntls(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kECDHEKyber) {
        if (!tls_construct_cke_ecdhekyber_ntls(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else if (alg_k & SSL_kKyberAigisEnc) {
        if (!tls_construct_cke_kyber_aigis_enc_dilithium_ntls(s, pkt)) {
            goto err;
        }
    } else if (alg_k & SSL_kKyber) {
        if (!tls_construct_cke_kyber_dilithium_ntls(s, pkt)) {
            goto err;
        }
    } else if (alg_k & (SSL_kSM2DHE)) {
        if (!tls_construct_cke_sm2dhe_ntls(s, pkt)) {
            /* SSLfatal_ntls() already called */
            goto err;
        }
    } else {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    /* Print key exchange information after constructing ClientKeyExchange */
    print_kex_info_client_cke(s, alg_k);
    
    return 1;
err:
    OPENSSL_clear_free(s->s3.tmp.pms, s->s3.tmp.pmslen);
    s->s3.tmp.pms = NULL;
    s->s3.tmp.pmslen = 0;
    return 0;
}

int tls_client_key_exchange_post_work_ntls(SSL *s)
{
    unsigned char *pms = NULL;
    size_t pmslen = 0;

    pms = s->s3.tmp.pms;
    pmslen = s->s3.tmp.pmslen;

    if (pms == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!ssl_generate_master_secret(s, pms, pmslen, 1)) {
        /* SSLfatal_ntls() already called */
        /* ssl_generate_master_secret frees the pms even on error */
        pms = NULL;
        pmslen = 0;
        goto err;
    }
    pms = NULL;
    pmslen = 0;

    return 1;
 err:
    OPENSSL_clear_free(pms, pmslen);
    s->s3.tmp.pms = NULL;
    s->s3.tmp.pmslen = 0;
    return 0;
}

/*
 * Check a certificate can be used for client authentication. Currently check
 * cert exists, if we have a suitable digest for TLS 1.2 if static DH client
 * certificates can be used and optionally checks suitability for Suite B.
 */
static int ssl3_check_client_certificate_ntls(SSL *s)
{
    /* If no suitable signature algorithm can't use certificate */
    if (!tls_choose_sigalg_ntls(s, 0) || s->s3.tmp.sigalg == NULL)
        return 0;

    /*
     * If strict mode check suitability of chain before using it. This also
     * adjusts suite B digest if necessary.
     */
    if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT &&
        !tls1_check_chain(s, NULL, NULL, NULL, -2))
        return 0;
    return 1;
}

WORK_STATE tls_prepare_client_certificate_ntls(SSL *s, WORK_STATE wst)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    int i;

    if (wst == WORK_MORE_A) {
        /* Let cert callback update client certificates if required */
        if (s->cert->cert_cb) {
            i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
            if (i < 0) {
                s->rwstate = SSL_X509_LOOKUP;
                return WORK_MORE_A;
            }
            if (i == 0) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_CALLBACK_FAILED);
                return WORK_ERROR;
            }
            s->rwstate = SSL_NOTHING;
        }
        if (ssl3_check_client_certificate_ntls(s)) {
            if (s->post_handshake_auth == SSL_PHA_REQUESTED) {
                return WORK_FINISHED_STOP;
            }
            return WORK_FINISHED_CONTINUE;
        }

        /* Fall through to WORK_MORE_B */
        wst = WORK_MORE_B;
    }

    /* We need to get a client cert */
    if (wst == WORK_MORE_B) {
        /*
         * If we get an error, we need to ssl->rwstate=SSL_X509_LOOKUP;
         * return(-1); We then get retied later
         */
        i = ssl_do_client_cert_cb_ntls(s, &x509, &pkey);
        if (i < 0) {
            s->rwstate = SSL_X509_LOOKUP;
            return WORK_MORE_B;
        }
        s->rwstate = SSL_NOTHING;
        if ((i == 1) && (pkey != NULL) && (x509 != NULL)) {
            if (!SSL_use_certificate(s, x509) || !SSL_use_PrivateKey(s, pkey))
                i = 0;
        } else if (i == 1) {
            i = 0;
            ERR_raise(ERR_LIB_SSL, SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
        }

        X509_free(x509);
        EVP_PKEY_free(pkey);
        if (i && !ssl3_check_client_certificate_ntls(s))
            i = 0;
        if (i == 0) {
            s->s3.tmp.cert_req = 2;
            if (!ssl3_digest_cached_records(s, 0)) {
                /* SSLfatal_ntls() already called */
                return WORK_ERROR;
            }
        }

        if (s->post_handshake_auth == SSL_PHA_REQUESTED)
            return WORK_FINISHED_STOP;
        return WORK_FINISHED_CONTINUE;
    }

    /* Shouldn't ever get here */
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    return WORK_ERROR;
}

int tls_construct_client_certificate_ntls(SSL *s, WPACKET *pkt)
{
    if (s->s3.tmp.cert_req) {
        X509 *sign_x509 = NULL;
        X509 *enc_x509 = NULL;

        if (s->s3.tmp.sign_cert != NULL)
            sign_x509 = s->s3.tmp.sign_cert->x509;
        if (s->s3.tmp.enc_cert != NULL)
            enc_x509 = s->s3.tmp.enc_cert->x509;
        if (sign_x509 == NULL)
            sign_x509 = s->cert->pkeys[SSL_PKEY_SM2_SIGN].x509;
        if (enc_x509 == NULL)
            enc_x509 = s->cert->pkeys[SSL_PKEY_SM2_ENC].x509;
        ntls_log_mutual_auth_send_certs("Client", sign_x509, enc_x509);
    }

    if (!ssl3_output_cert_chain_ntls(s, pkt,
            (s->s3.tmp.cert_req == 2) ? NULL : s->s3.tmp.sign_cert,
            (s->s3.tmp.cert_req == 2) ? NULL : s->s3.tmp.enc_cert)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }

    return 1;
}

int ssl3_check_cert_and_algorithm_ntls(SSL *s)
{
    const SSL_CERT_LOOKUP *clu;
    size_t idx;
    long alg_k, alg_a;

    alg_k = s->s3.tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3.tmp.new_cipher->algorithm_auth;

    /* we don't have a certificate */
    if (!(alg_a & SSL_aCERT))
        return 1;

    /* This is the passed certificate */
    clu = ssl_cert_lookup_by_pkey(X509_get0_pubkey(s->session->peer), &idx);

    /* Check certificate is recognised and suitable for cipher */
    if (clu == NULL || (alg_a & clu->amask) == 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_MISSING_SIGNING_CERT);
        return 0;
    }

    if (clu->amask & SSL_aECDSA) {
        if (ssl_check_srvr_ecc_cert_and_alg(s->session->peer, s))
            return 1;
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_BAD_ECC_CERT);
        return 0;
    }

    if (alg_k & (SSL_kRSA | SSL_kRSAPSK) && idx != SSL_PKEY_RSA) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE,
		              SSL_R_MISSING_RSA_ENCRYPTING_CERT);
        return 0;
    }

    if ((alg_k & SSL_kDHE) && (s->s3.peer_tmp == NULL)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_next_proto_ntls(SSL *s, WPACKET *pkt)
{
    size_t len, padding_len;
    unsigned char *padding = NULL;

    len = s->ext.npn_len;
    padding_len = 32 - ((len + 2) % 32);

    if (!WPACKET_sub_memcpy_u8(pkt, s->ext.npn, len)
            || !WPACKET_sub_allocate_bytes_u8(pkt, padding_len, &padding)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memset(padding, 0, padding_len);

    return 1;
}
#endif

MSG_PROCESS_RETURN tls_process_hello_req_ntls(SSL *s, PACKET *pkt)
{
    if (PACKET_remaining(pkt) > 0) {
        /* should contain no data */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if ((s->options & SSL_OP_NO_RENEGOTIATION)) {
        ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
        return MSG_PROCESS_FINISHED_READING;
    }

    /*
     * This is a historical discrepancy (not in the RFC) maintained for
     * compatibility reasons. If a TLS client receives a HelloRequest it will
     * attempt an abbreviated handshake. However if a DTLS client receives a
     * HelloRequest it will do a full handshake. Either behaviour is reasonable
     * but doing one for TLS and another for DTLS is odd.
     */
    SSL_renegotiate_abbreviated(s);

    return MSG_PROCESS_FINISHED_READING;
}

int ssl_do_client_cert_cb_ntls(SSL *s, X509 **px509, EVP_PKEY **ppkey)
{
    int i = 0;
#ifndef OPENSSL_NO_ENGINE
    if (s->ctx->client_cert_engine) {
        i = tls_engine_load_ssl_client_cert(s, px509, ppkey);
        if (i != 0)
            return i;
    }
#endif
    if (s->ctx->client_cert_cb)
        i = s->ctx->client_cert_cb(s, px509, ppkey);
    return i;
}

int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)
{
    int i;
    size_t totlen = 0, len, maxlen, maxverok = 0;
    int empty_reneg_info_scsv = !s->renegotiate;

    /* Set disabled masks for this session */
    if (!ssl_set_client_disabled(s)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_NO_PROTOCOLS_AVAILABLE);
        return 0;
    }

    if (sk == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
# if OPENSSL_MAX_TLS1_2_CIPHER_LENGTH < 6
#  error Max cipher length too short
# endif
    /*
     * Some servers hang if client hello > 256 bytes as hack workaround
     * chop number of supported ciphers to keep it well below this if we
     * use TLS v1.2
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION)
        maxlen = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
    else
#endif
        /* Maximum length that can be stored in 2 bytes. Length must be even */
        maxlen = 0xfffe;

    if (empty_reneg_info_scsv)
        maxlen -= 2;
    if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV)
        maxlen -= 2;

    for (i = 0; i < sk_SSL_CIPHER_num(sk) && totlen < maxlen; i++) {
        const SSL_CIPHER *c;

        c = sk_SSL_CIPHER_value(sk, i);
        /* Skip disabled ciphers */
        if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED, 0))
            continue;

        if (!s->method->put_cipher_by_char(c, pkt, &len)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /* Sanity check that the maximum version we offer has ciphers enabled */
        if (!maxverok) {
            if (c->max_tls >= s->s3.tmp.max_ver
                    && c->min_tls <= s->s3.tmp.max_ver)
                maxverok = 1;

        }

        totlen += len;
    }

    if (totlen == 0 || !maxverok) {
        const char *maxvertext =
            !maxverok
            ? "No ciphers enabled for max supported SSL/TLS version"
            : NULL;

        SSLfatal_data_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_R_NO_CIPHERS_AVAILABLE,
                      maxvertext);
        return 0;
    }

    if (totlen != 0) {
        if (empty_reneg_info_scsv) {
            static SSL_CIPHER scsv = {
                0, NULL, NULL, SSL3_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
        if (s->mode & SSL_MODE_SEND_FALLBACK_SCSV) {
            static SSL_CIPHER scsv = {
                0, NULL, NULL, SSL3_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            if (!s->method->put_cipher_by_char(&scsv, pkt, &len)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    return 1;
}

int tls_construct_end_of_early_data_ntls(SSL *s, WPACKET *pkt)
{
    if (s->early_data_state != SSL_EARLY_DATA_WRITE_RETRY
            && s->early_data_state != SSL_EARLY_DATA_FINISHED_WRITING) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    s->early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;
    return 1;
}

