/*
 *  Public Key layer for parsing key files and structures
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/pem.h"
#include "mbedtls/oid.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define PK_VALIDATE_RET( cond ) do {} while (0)
#define PK_VALIDATE( cond ) do {} while (0)

/*
 * Initialise a mbedtls_pk_context
 */
void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    PK_VALIDATE( ctx != NULL );

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a mbedtls_pk_context
 */
void mbedtls_pk_free( mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pk_context ) );
}

/*
 * Get pk_info structure from type
 */
const mbedtls_pk_info_t * mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return( &mbedtls_rsa_info );
#endif
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
}

/*
 * Initialise context
 */
int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info )
{
    PK_VALIDATE_RET( ctx != NULL );
    if( info == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}


#if defined(MBEDTLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /* Import N */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( ( ret = mbedtls_rsa_import_raw( rsa, *p, len, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY );

    *p += len;

    /* Import E */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( ( ret = mbedtls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, *p, len ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY );

    *p += len;

    if( mbedtls_rsa_complete( rsa ) != 0 ||
        mbedtls_rsa_check_pubkey( rsa ) != 0 )
    {
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY );
    }

    if( *p != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params )
{
    int ret;
    mbedtls_asn1_buf alg_oid;

    memset( params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_ALG + ret );

    if( mbedtls_oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    /*
     * No parameters with RSA (only for EC)
     */
    if( *pk_alg == MBEDTLS_PK_RSA &&
            ( ( params->tag != MBEDTLS_ASN1_NULL && params->tag != 0 ) ||
                params->len != 0 ) )
    {
        return( MBEDTLS_ERR_PK_INVALID_ALG );
    }

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int mbedtls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedtls_pk_context *pk )
{
    int ret;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    PK_VALIDATE_RET( p != NULL );
    PK_VALIDATE_RET( *p != NULL );
    PK_VALIDATE_RET( end != NULL );
    PK_VALIDATE_RET( pk != NULL );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        ret = pk_get_rsapubkey( p, end, mbedtls_pk_rsa( *pk ) );
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( pk_alg == MBEDTLS_PK_ECKEY_DH || pk_alg == MBEDTLS_PK_ECKEY )
    {
        ret = pk_use_ecparams( &alg_params, &mbedtls_pk_ec( *pk )->grp );
        if( ret == 0 )
            ret = pk_get_ecpubkey( p, end, mbedtls_pk_ec( *pk ) );
    } else
#endif /* MBEDTLS_ECP_C */
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    if( ret == 0 && *p != end )
        ret = MBEDTLS_ERR_PK_INVALID_PUBKEY
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    if( ret != 0 )
        mbedtls_pk_free( pk );

    return( ret );
}

#if defined(MBEDTLS_RSA_C)
/*
 * Parse a PKCS#1 encoded private RSA key
 */
static int pk_parse_key_pkcs1_der( mbedtls_rsa_context *rsa,
                                   const unsigned char *key,
                                   size_t keylen )
{
    int ret, version;
    size_t len;
    unsigned char *p, *end;

    mbedtls_mpi T;
    mbedtls_mpi_init( &T );

    p = (unsigned char *) key;
    end = p + keylen;

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( version != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION );
    }

    /* Import N */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = mbedtls_rsa_import_raw( rsa, p, len, NULL, 0, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import E */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = mbedtls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        NULL, 0, p, len ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import D */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = mbedtls_rsa_import_raw( rsa, NULL, 0, NULL, 0, NULL, 0,
                                        p, len, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import P */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = mbedtls_rsa_import_raw( rsa, NULL, 0, p, len, NULL, 0,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Import Q */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 ||
        ( ret = mbedtls_rsa_import_raw( rsa, NULL, 0, NULL, 0, p, len,
                                        NULL, 0, NULL, 0 ) ) != 0 )
        goto cleanup;
    p += len;

    /* Complete the RSA private key */
    if( ( ret = mbedtls_rsa_complete( rsa ) ) != 0 )
        goto cleanup;

    /* Check optional parameters */
    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &T ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &T ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &T ) ) != 0 )
        goto cleanup;

    if( p != end )
    {
        ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ;
    }

cleanup:

    mbedtls_mpi_free( &T );

    if( ret != 0 )
    {
        /* Wrap error code if it's coming from a lower level */
        if( ( ret & 0xff80 ) == 0 )
            ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
        else
            ret = MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;

        mbedtls_rsa_free( rsa );
    }

    return( ret );
}
#endif /* MBEDTLS_RSA_C */

/*
 * Parse an unencrypted PKCS#8 encoded private key
 *
 * Notes:
 *
 * - This function does not own the key buffer. It is the
 *   responsibility of the caller to take care of zeroizing
 *   and freeing it after use.
 *
 * - The function is responsible for freeing the provided
 *   PK context on failure.
 *
 */
static int pk_parse_key_pkcs8_unencrypted_der(
                                    mbedtls_pk_context *pk,
                                    const unsigned char* key,
                                    size_t keylen )
{
    int ret, version;
    size_t len;
    mbedtls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    /*
     * This function parses the PrivateKeyInfo object (PKCS#8 v1.2 = RFC 5208)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     *
     *  The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
     */

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION + ret );

    if( ( ret = pk_get_pk_alg( &p, end, &pk_alg, &params ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( len < 1 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        if( ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), p, len ) ) != 0 )
        {
            mbedtls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* MBEDTLS_RSA_C */
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    return( 0 );
}

/*
 * Parse a private key
 */
int mbedtls_pk_parse_key( mbedtls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret;
    const mbedtls_pk_info_t *pk_info;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;
#endif

    PK_VALIDATE_RET( pk != NULL );
    if( keylen == 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
    PK_VALIDATE_RET( key != NULL );

#if defined(MBEDTLS_PEM_PARSE_C)
   mbedtls_pem_init( &pem );

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PRIVATE KEY-----",
                               "-----END RSA PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );

    if( ret == 0 )
    {
        pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA );
        if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 ||
            ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ),
                                            pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH )
        return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED )
        return( MBEDTLS_ERR_PK_PASSWORD_REQUIRED );
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* MBEDTLS_RSA_C */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN PRIVATE KEY-----",
                               "-----END PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk,
                                                pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );

#else
    ((void) pwd);
    ((void) pwdlen);
#endif /* MBEDTLS_PEM_PARSE_C */

    /*
     * At this point we only know it's not a PEM formatted key. Could be any
     * of the known DER encoded private key formats
     *
     * We try the different DER format parsers to see if one passes without
     * error
     */
    if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk, key, keylen ) ) == 0 )
        return( 0 );

    mbedtls_pk_free( pk );
    mbedtls_pk_init( pk );

#if defined(MBEDTLS_RSA_C)

    pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA );
    if( mbedtls_pk_setup( pk, pk_info ) == 0 &&
        pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), key, keylen ) == 0 )
    {
        return( 0 );
    }

    mbedtls_pk_free( pk );
    mbedtls_pk_init( pk );
#endif /* MBEDTLS_RSA_C */

    /* If MBEDTLS_RSA_C is defined but MBEDTLS_ECP_C isn't,
     * it is ok to leave the PK context initialized but not
     * freed: It is the caller's responsibility to call pk_init()
     * before calling this function, and to call pk_free()
     * when it fails. If MBEDTLS_ECP_C is defined but MBEDTLS_RSA_C
     * isn't, this leads to mbedtls_pk_free() being called
     * twice, once here and once by the caller, but this is
     * also ok and in line with the mbedtls_pk_free() calls
     * on failed PEM parsing attempts. */

    return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
}

/*
 * Parse a public key
 */
int mbedtls_pk_parse_public_key( mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char *p;
#if defined(MBEDTLS_RSA_C)
    const mbedtls_pk_info_t *pk_info;
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;
#endif

    PK_VALIDATE_RET( ctx != NULL );
    if( keylen == 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
    PK_VALIDATE_RET( key != NULL || keylen == 0 );

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init( &pem );
#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PUBLIC KEY-----",
                               "-----END RSA PUBLIC KEY-----",
                               key, NULL, 0, &len );

    if( ret == 0 )
    {
        p = pem.buf;
        if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
            return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

        if( ( ret = mbedtls_pk_setup( ctx, pk_info ) ) != 0 )
            return( ret );

        if ( ( ret = pk_get_rsapubkey( &p, p + pem.buflen, mbedtls_pk_rsa( *ctx ) ) ) != 0 )
            mbedtls_pk_free( ctx );

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        mbedtls_pem_free( &pem );
        return( ret );
    }
#endif /* MBEDTLS_RSA_C */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                key, NULL, 0, &len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded
         */
        p = pem.buf;

        ret = mbedtls_pk_parse_subpubkey( &p,  p + pem.buflen, ctx );
        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        mbedtls_pem_free( &pem );
        return( ret );
    }
    mbedtls_pem_free( &pem );
#endif /* MBEDTLS_PEM_PARSE_C */

#if defined(MBEDTLS_RSA_C)
    if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( ctx, pk_info ) ) != 0 )
        return( ret );

    p = (unsigned char *)key;
    ret = pk_get_rsapubkey( &p, p + keylen, mbedtls_pk_rsa( *ctx ) );
    if( ret == 0 )
    {
        return( ret );
    }
    mbedtls_pk_free( ctx );
    if( ret != ( MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
    {
        return( ret );
    }
#endif /* MBEDTLS_RSA_C */
    p = (unsigned char *) key;

    ret = mbedtls_pk_parse_subpubkey( &p, p + keylen, ctx );

    return( ret );
}

#endif /* MBEDTLS_PK_PARSE_C */
