/*
 *  Privacy Enhanced Mail (PEM) decoding
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

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)

#include "mbedtls/pem.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
void mbedtls_pem_init( mbedtls_pem_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_pem_context ) );
}

int mbedtls_pem_read_buffer( mbedtls_pem_context *ctx, const char *header, const char *footer,
                     const unsigned char *data, const unsigned char *pwd,
                     size_t pwdlen, size_t *use_len )
{
    int ret, enc;
    size_t len;
    unsigned char *buf;
    const unsigned char *s1, *s2, *end;
#if defined(MBEDTLS_MD5_C) && defined(MBEDTLS_CIPHER_MODE_CBC) &&         \
    ( defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C) )
    unsigned char pem_iv[16];
    mbedtls_cipher_type_t enc_alg = MBEDTLS_CIPHER_NONE;
#else
    ((void) pwd);
    ((void) pwdlen);
#endif /* MBEDTLS_MD5_C && MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

    if( ctx == NULL )
        return( MBEDTLS_ERR_PEM_BAD_INPUT_DATA );

    s1 = (unsigned char *) strstr( (const char *) data, header );

    if( s1 == NULL )
        return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s2 = (unsigned char *) strstr( (const char *) data, footer );

    if( s2 == NULL || s2 <= s1 )
        return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    s1 += strlen( header );
    if( *s1 == ' '  ) s1++;
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;
    else return( MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT );

    end = s2;
    end += strlen( footer );
    if( *end == ' '  ) end++;
    if( *end == '\r' ) end++;
    if( *end == '\n' ) end++;
    *use_len = end - data;

    enc = 0;

    if( s2 - s1 >= 22 && memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
    {
        return( MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE );
    }

    if( s1 >= s2 )
        return( MBEDTLS_ERR_PEM_INVALID_DATA );

    ret = base64_decode( NULL, 0, &len, s1, s2 - s1 );

    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        return( MBEDTLS_ERR_PEM_INVALID_DATA + ret );

    if( ( buf = mbedtls_calloc( 1, len ) ) == NULL )
        return( MBEDTLS_ERR_PEM_ALLOC_FAILED );

    if( ( ret = mbedtls_base64_decode( buf, len, &len, s1, s2 - s1 ) ) != 0 )
    {
        mbedtls_platform_zeroize( buf, len );
        mbedtls_free( buf );
        return( MBEDTLS_ERR_PEM_INVALID_DATA + ret );
    }

    if( enc != 0 )
    {
        mbedtls_platform_zeroize( buf, len );
        mbedtls_free( buf );
        return( MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE );
    }

    ctx->buf = buf;
    ctx->buflen = len;

    return( 0 );
}

void mbedtls_pem_free( mbedtls_pem_context *ctx )
{
    if( ctx->buf != NULL )
        mbedtls_platform_zeroize( ctx->buf, ctx->buflen );
    mbedtls_free( ctx->buf );
    mbedtls_free( ctx->info );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pem_context ) );
}
#endif /* MBEDTLS_PEM_PARSE_C */

#endif /* MBEDTLS_PEM_PARSE_C || MBEDTLS_PEM_WRITE_C */
