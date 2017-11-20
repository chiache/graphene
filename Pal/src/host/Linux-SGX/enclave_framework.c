/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>
#include <list.h>

#include "enclave_pages.h"

struct pal_enclave_state pal_enclave_state;

void * enclave_base, * enclave_top;

struct pal_enclave_config pal_enclave_config;

bool sgx_is_within_enclave (const void * addr, uint64_t size)
{
    return (addr >= enclave_base &&
            addr + size <= enclave_top) ? 1 : 0;
}

void * sgx_ocalloc (uint64_t size)
{
    void * ustack = GET_ENCLAVE_TLS(ustack) - size;
    SET_ENCLAVE_TLS(ustack, ustack);
    return ustack;
}

void * sgx_ocalloc_top (int64_t offset)
{
    void * ustack_top = GET_ENCLAVE_TLS(ustack_top),
         * ustack = GET_ENCLAVE_TLS(ustack);

    assert(ustack_top == ustack);

    ustack_top -= offset;
    SET_ENCLAVE_TLS(ustack_top, ustack_top);
    SET_ENCLAVE_TLS(ustack, ustack_top);

    return ustack_top;
}

void sgx_ocfree (void)
{
    SET_ENCLAVE_TLS(ustack, GET_ENCLAVE_TLS(ustack_top));
}

int sgx_get_report (sgx_arch_hash_t * mrenclave,
                    sgx_arch_attributes_t * attributes,
                    void * enclave_data,
                    sgx_arch_report_t * report)
{
    sgx_arch_targetinfo_t targetinfo;

    memset(&targetinfo, 0, sizeof(sgx_arch_targetinfo_t));
    memcpy(targetinfo.mrenclave, mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&targetinfo.attributes, attributes, sizeof(sgx_arch_attributes_t));

    struct pal_enclave_state state;
    memcpy(&state, &pal_enclave_state, sizeof(struct pal_enclave_state));
    memcpy(&state.data, enclave_data, PAL_ATTESTATION_DATA_SIZE);

    int ret = sgx_report(&targetinfo, &state, report);
    if (ret)
        return -PAL_ERROR_DENIED;

    SGX_DBG(DBG_S, "Generated report:\n");
    SGX_DBG(DBG_S, "    cpusvn:           %08x %08x\n", report->cpusvn[0],
                                                report->cpusvn[1]);
    SGX_DBG(DBG_S, "    mrenclave:        %s\n",        hex2str(report->mrenclave));
    SGX_DBG(DBG_S, "    mrsigner:         %s\n",        hex2str(report->mrsigner));
    SGX_DBG(DBG_S, "    attributes.flags: %016lx\n",    report->attributes.flags);
    SGX_DBG(DBG_S, "    sttributes.xfrm:  %016lx\n",    report->attributes.xfrm);

    SGX_DBG(DBG_S, "    isvprodid:        %02x\n",      report->isvprodid);
    SGX_DBG(DBG_S, "    isvsvn:           %02x\n",      report->isvsvn);
    SGX_DBG(DBG_S, "    keyid:            %s\n",        hex2str(report->keyid));
    SGX_DBG(DBG_S, "    mac:              %s\n",        hex2str(report->mac));

    return 0;
}

static sgx_arch_key128_t enclave_key;

int sgx_verify_report (sgx_arch_report_t * report)
{
#if 0
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = REPORT_KEY;
    memcpy(keyrequest.keyid, report->keyid, sizeof(keyrequest.keyid));

    int ret = sgx_getkey(&keyrequest, &enclave_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get report key for verification: %s\n", hex2str(enclave_key));
#endif
    return 0;
}

int init_enclave_key (void)
{
#if 0
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = SEAL_KEY;

    int ret = sgx_getkey(&keyrequest, &enclave_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }
#endif
    _DkRandomBitsRead(&enclave_key, sizeof(enclave_key));
    SGX_DBG(DBG_S, "Get sealing key: %s\n", hex2str(enclave_key));
    return 0;
}

DEFINE_LIST(trusted_file);
struct trusted_file {
    LIST_TYPE(trusted_file) list;
    int64_t index;
    uint64_t size;
    int uri_len;
    char uri[URI_MAX];
    sgx_checksum_t checksum;
    sgx_stub_t * stubs;
};

DEFINE_LISTP(trusted_file);
static LISTP_TYPE(trusted_file) trusted_file_list = LISTP_INIT;
static struct spinlock trusted_file_lock = LOCK_INIT;
static int trusted_file_indexes = 0;

int load_trusted_file (PAL_HANDLE file, sgx_stub_t ** stubptr,
                       uint64_t * sizeptr)
{
    struct trusted_file * tf = NULL, * tmp;
    char uri[URI_MAX];
    char normpath[URI_MAX];
    int ret, fd = HANDLE_HDR(file)->fds[0], uri_len, len;

    if (!(HANDLE_HDR(file)->flags & RFD(0))) 
        return -PAL_ERROR_DENIED;

    uri_len = _DkStreamGetName(file, uri, URI_MAX);
    if (uri_len < 0)
        return uri_len;

    /* Normalize the uri */
    if (!strpartcmp_static(uri, "file:")) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);;
        return -PAL_ERROR_INVAL;
    }
    normpath [0] = 'f';
    normpath [1] = 'i';
    normpath [2] = 'l';
    normpath [3] = 'e';
    normpath [4] = ':';
    len = get_norm_path(uri + 5, normpath + 5, 0, URI_MAX);
    uri_len = len + 5;

    _DkSpinLock(&trusted_file_lock);

    listp_for_each_entry(tmp, &trusted_file_list, list) {
        if (tmp->stubs) {
            /* trusted files: must be exactly the same URI */
            if (tmp->uri_len == uri_len && !memcmp(tmp->uri, normpath, uri_len + 1)) {
                tf = tmp;
                break;
            }
        } else {
            /* allowed files: must be a subfolder or file */
            if (tmp->uri_len <= uri_len &&
                !memcmp(tmp->uri, normpath, tmp->uri_len) &&
                (!normpath[tmp->uri_len] || normpath[tmp->uri_len] == '/')) {
                tf = tmp;
                break;
            }
        }
    }

    _DkSpinUnlock(&trusted_file_lock);

    if (!tf)
        return -PAL_ERROR_DENIED;

    if (tf->index < 0)
        return tf->index;

#if CACHE_FILE_STUBS == 1
    if (tf->index && tf->stubs) {
        *stubptr = tf->stubs;
        *sizeptr = tf->size;
        return 0;
    }
#endif

    if (!tf->index) {
        *stubptr = NULL;
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(normpath, &attr);
        if (!ret)
            *sizeptr = attr.pending_size;
        else
            *sizeptr = 0;
        return 0;
    }

    int nstubs = tf->size / TRUSTED_STUB_SIZE +
                (tf->size % TRUSTED_STUB_SIZE ? 1 : 0);

    sgx_stub_t * stubs = malloc(sizeof(sgx_stub_t) * nstubs);
    if (!stubs)
        return -PAL_ERROR_NOMEM;

    sgx_stub_t * s = stubs;
    uint64_t offset = 0;
    LIB_SHA256_CONTEXT sha;
    void * umem;

    ret = lib_SHA256Init(&sha);
    if (ret < 0)
        goto failed;

    for (; offset < tf->size ; offset += TRUSTED_STUB_SIZE, s++) {
        uint64_t mapping_size = tf->size - offset;
        if (mapping_size > TRUSTED_STUB_SIZE)
            mapping_size = TRUSTED_STUB_SIZE;

        ret = ocall_map_untrusted(fd, offset, mapping_size, PROT_READ, &umem);
        if (ret < 0)
            goto unmap;

        lib_AESCMAC((void *) &enclave_key, AES_CMAC_KEY_LEN, umem,
                    mapping_size, (uint8_t *) s, sizeof *s);

        /* update the file checksum */
        ret = lib_SHA256Update(&sha, umem, mapping_size);

unmap:
        ocall_unmap_untrusted(umem, mapping_size);
        if (ret < 0)
            goto failed;
    }

    sgx_checksum_t hash;

    ret = lib_SHA256Final(&sha, (uint8_t *) hash.bytes);
    if (ret < 0)
        goto failed;

    SGX_DBG(DBG_S, "verfied: %s %s\n", uri, hex2str(hash.bytes));

    if (memcmp(&hash, &tf->checksum, sizeof(sgx_checksum_t))) {
        ret = -PAL_ERROR_DENIED;
        goto failed;
    }

    _DkSpinLock(&trusted_file_lock);
    if (tf->stubs || tf->index == -PAL_ERROR_DENIED)
        free(tf->stubs);
    *stubptr = tf->stubs = stubs;
    *sizeptr = tf->size;
    ret = tf->index;
    _DkSpinUnlock(&trusted_file_lock);
    return ret;

failed:
    free(stubs);

    _DkSpinLock(&trusted_file_lock);
    if (tf->stubs) {
        *stubptr = tf->stubs;
        *sizeptr = tf->size;
        ret = tf->index;
    } else {
        tf->index = -PAL_ERROR_DENIED;
    }
    _DkSpinUnlock(&trusted_file_lock);

#if PRINT_ENCLAVE_STAT
    if (!ret) {
        sgx_stub_t * loaded_stub;
        uint64_t loaded_size;
        PAL_HANDLE handle = NULL;
        if (!_DkStreamOpen(&handle, normpath, PAL_ACCESS_RDONLY, 0, 0, 0))
            load_trusted_file (handle, &loaded_stub, &loaded_size);
    }
#endif

    return ret;
}

int verify_trusted_file (const char * uri, void * mem,
                         unsigned int offset, unsigned int size,
                         sgx_stub_t * stubs,
                         unsigned int total_size)
{
    unsigned long checking = offset;
    sgx_stub_t * s = stubs + checking / TRUSTED_STUB_SIZE;

    for (; checking < offset + size ; checking += TRUSTED_STUB_SIZE, s++) {
        unsigned long checking_size = TRUSTED_STUB_SIZE;
        if (checking_size > total_size - checking)
            checking_size = total_size - checking;

        uint8_t hash[AES_CMAC_DIGEST_LEN];
        lib_AESCMAC((void *) &enclave_key,
                    AES_CMAC_KEY_LEN,
                    mem + checking - offset, checking_size,
                    hash, sizeof(hash));

        if (memcmp(s, hash, sizeof(sgx_stub_t))) {
            SGX_DBG(DBG_E, "Accesing file:%s is denied. "
                    "Does not match with its MAC.\n", uri);
            return -PAL_ERROR_DENIED;
        }
    }

    return 0;
}

static int register_trusted_file (const char * uri, const char * checksum_str)
{
    struct trusted_file * tf = NULL, * new;
    int uri_len = strlen(uri);
    int ret;

    _DkSpinLock(&trusted_file_lock);

    listp_for_each_entry(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            return 0;
        }
    }
    _DkSpinUnlock(&trusted_file_lock);

    new = malloc(sizeof(struct trusted_file));
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    new->uri_len = uri_len;
    memcpy(new->uri, uri, uri_len + 1);
    new->size = 0;
    new->stubs = NULL;

    if (checksum_str) {
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(uri, &attr);
        if (!ret)
            new->size = attr.pending_size;

        char checksum_text[sizeof(sgx_checksum_t) * 2 + 1] = "\0";
        int nbytes = 0;
        for (; nbytes < sizeof(sgx_checksum_t) ; nbytes++) {
            char byte1 = checksum_str[nbytes * 2];
            char byte2 = checksum_str[nbytes * 2 + 1];
            unsigned char val = 0;

            if (byte1 == 0 || byte2 == 0) {
                break;
            }
            if (!(byte1 >= '0' && byte1 <= '9') &&
                !(byte1 >= 'a' && byte1 <= 'f')) {
                break;
            }
            if (!(byte2 >= '0' && byte2 <= '9') &&
                !(byte2 >= 'a' && byte2 <= 'f')) {
                break;
            }

            if (byte1 >= '0' && byte1 <= '9')
                val = byte1 - '0';
            if (byte1 >= 'a' && byte1 <= 'f')
                val = byte1 - 'a' + 10;
            val *= 16;
            if (byte2 >= '0' && byte2 <= '9')
                val += byte2 - '0';
            if (byte2 >= 'a' && byte2 <= 'f')
                val += byte2 - 'a' + 10;

            new->checksum.bytes[nbytes] = val;
            snprintf(checksum_text + nbytes * 2, 3, "%02x", val);
        }

        if (nbytes < sizeof(sgx_checksum_t)) {
            free(new);
            return -PAL_ERROR_INVAL;
        }

        new->index = (++trusted_file_indexes);
        SGX_DBG(DBG_S, "trusted: [%d] %s %s\n", new->index,
                checksum_text, new->uri);
    } else {
        memset(&new->checksum, 0, sizeof(sgx_checksum_t));
        new->index = 0;
        SGX_DBG(DBG_S, "allowed: %s\n", new->uri);
    }

    _DkSpinLock(&trusted_file_lock);

    listp_for_each_entry(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            free(new);
            return 0;
        }
    }

    listp_add_tail(new, &trusted_file_list, list);
    _DkSpinUnlock(&trusted_file_lock);
    return 0;
}

static int init_trusted_file (const char * key, const char * uri)
{
    char cskey[URI_MAX], * tmp;
    char checksum[URI_MAX];
    char normpath[URI_MAX];
    
    tmp = strcpy_static(cskey, "sgx.trusted_checksum.", URI_MAX);
    memcpy(tmp, key, strlen(key) + 1);

    int len = get_config(pal_state.root_config, cskey, checksum, CONFIG_MAX);
    if (len < 0)
        return 0;

    /* Normalize the uri */
    if (!strpartcmp_static(uri, "file:")) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);
        return -PAL_ERROR_INVAL;
    }
    normpath [0] = 'f';
    normpath [1] = 'i';
    normpath [2] = 'l';
    normpath [3] = 'e';
    normpath [4] = ':';
    len = get_norm_path(uri + 5, normpath + 5, 0, URI_MAX);

    return register_trusted_file(normpath, checksum);
}

int init_trusted_files (void)
{
    char cfgbuf[CONFIG_MAX];
    int ret;

    if (pal_sec.exec_fd != PAL_IDX_POISON) {
        ret = init_trusted_file("exec", pal_sec.exec_name);
        if (ret < 0)
            return ret;
    }

    int len = get_config(pal_state.root_config, "loader.preload",
                         cfgbuf, CONFIG_MAX);
    if (len) {
        int npreload = 0;
        char key[10];
        const char * start, * end;

        for (start = cfgbuf ; start < cfgbuf + len ; start = end + 1) {
            for (end = start ; end < cfgbuf + len && *end && *end != ',' ; end++);
            if (end > start) {
                char uri[end - start + 1];
                memcpy(uri, start, end - start);
                uri[end - start] = 0;
                snprintf(key, 10, "preload%d", npreload++);

                ret = init_trusted_file(key, uri);
                if (ret < 0)
                    return ret;
            }
        }
    }

    int nuris = get_config_entries(pal_state.root_config, "sgx.trusted_files",
                                   cfgbuf, CONFIG_MAX);
    if (nuris) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.trusted_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0) {
                ret = init_trusted_file(tmp, uri);
                if (ret < 0)
                    return ret;
            }
        }
    }

    nuris = get_config_entries(pal_state.root_config, "sgx.trusted_libs",
                                   cfgbuf, CONFIG_MAX);
    if (nuris) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.trusted_libs.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0) {
                ret = init_trusted_file(tmp, uri);
                if (ret < 0)
                    return ret;
            }
        }
    }

    nuris = get_config_entries(pal_state.root_config, "sgx.allowed_files",
                               cfgbuf, CONFIG_MAX);
    if (nuris > 0) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.allowed_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0)
                register_trusted_file(uri, NULL);
        }
    }

    
    return 0;
}

int init_trusted_children (void)
{
    char cfgbuf[CONFIG_MAX];
    char key[CONFIG_MAX], mrkey[CONFIG_MAX];
    char uri[CONFIG_MAX], mrenclave[CONFIG_MAX];

    char * tmp1 = strcpy_static(key, "sgx.trusted_children.", CONFIG_MAX);
    char * tmp2 = strcpy_static(mrkey, "sgx.trusted_mrenclave.", CONFIG_MAX);

    int nuris = get_config_entries(pal_state.root_config,
                                   "sgx.trusted_mrenclave", cfgbuf, CONFIG_MAX);
    if (nuris > 0) {
        char * k = cfgbuf;
        for (int i = 0 ; i < nuris ; i++) {
            int len = strlen(k);
            memcpy(tmp1, k, len + 1);
            memcpy(tmp2, k, len + 1);
            k += len + 1;

            int ret = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (ret < 0)
                continue;

            ret = get_config(pal_state.root_config, mrkey, mrenclave,
                             CONFIG_MAX);
            if (ret > 0)
                register_trusted_child(uri, mrenclave);
        }
    }

    return 0;
}

#if 0
void test_dh (void)
{
    int ret;
    DhKey key1, key2;
    uint32_t privsz1, privsz2, pubsz1, pubsz2, agreesz1, agreesz2;
    unsigned char priv1[128], pub1[128], priv2[128], pub2[128], agree1[128],
                  agree2[128];

    InitDhKey(&key1);
    InitDhKey(&key2);

    ret = DhSetKey(&key1, dh_param.p, sizeof(dh_param.p), dh_param.g,
                   sizeof(dh_param.g));
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhSetKey for key 1 failed: %d\n", ret);
        return;
    }
    ret = DhSetKey(&key2, dh_param.p, sizeof(dh_param.p), dh_param.g,
                   sizeof(dh_param.g));
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhSetKey for key 2 failed: %d\n", ret);
        return;
    }

    ret = DhGenerateKeyPair(&key1, priv1, &privsz1, pub1, &pubsz1);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhGenerateKeyPair for key 1 failed: %d\n", ret);
        return;
    }
    ret = DhGenerateKeyPair(&key2, priv2, &privsz2, pub2, &pubsz2);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhGenerateKeyPair for key 2 failed: %d\n", ret);
        return;
    }

    ret = DhAgree(&key1, agree1, &agreesz1, priv1, privsz1, pub2, pubsz2);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhAgree for key 1 failed: %d\n", ret);
        return;
    }

    ret = DhAgree(&key2, agree2, &agreesz2, priv2, privsz2, pub1, pubsz1);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhAgree for key 1 failed: %d\n", ret);
        return;
    }

    FreeDhKey(&key1);
    FreeDhKey(&key2);

    SGX_DBG(DBG_S, "key exchange(side A): %s (%d)\n", __hex2str(agree1, agreesz1),
           agreesz1);
    SGX_DBG(DBG_S, "key exchange(side B): %s (%d)\n", __hex2str(agree2, agreesz2),
           agreesz2);
}
#endif

#define RSA_KEY_SIZE        2048
#define RSA_E               3

int init_enclave (void)
{
    int ret;
    LIB_RSA_KEY *rsa = malloc(sizeof(LIB_RSA_KEY));
    lib_RSAInitKey(rsa);

    ret = lib_RSAGenerateKey(rsa, RSA_KEY_SIZE, RSA_E);
    if (ret != 0) {
        SGX_DBG(DBG_S, "lib_RSAGenerateKey failed: %d\n", ret);
        return ret;
    }

    PAL_NUM nsz = RSA_KEY_SIZE / 8, esz = 1;
    uint8_t n[nsz], e[esz];

    ret = lib_RSAExportPublicKey(rsa, e, &esz, n, &nsz);
    if (ret != 0) {
        SGX_DBG(DBG_S, "lib_RSAExtractPublicKey failed: %d\n", ret);
        goto out_free;
    }

    LIB_SHA256_CONTEXT sha256;

    ret = lib_SHA256Init(&sha256);
    if (ret < 0)
        goto out_free;

    ret = lib_SHA256Update(&sha256, n, nsz);
    if (ret < 0)
        goto out_free;

    ret = lib_SHA256Final(&sha256, (uint8_t *) pal_enclave_state.enclave_keyhash);
    if (ret < 0)
        goto out_free;

    pal_enclave_config.enclave_key = rsa;

    SGX_DBG(DBG_S, "enclave (software) key hash: %s\n",
           hex2str(pal_enclave_state.enclave_keyhash));

    return 0;

out_free:
    lib_RSAFreeKey(rsa);
    free(rsa);
    return ret;
}

int _DkStreamKeyExchange (PAL_HANDLE stream, PAL_SESSION_KEY * keyptr,
                          handle_read_t read, handle_write_t write)
{
    unsigned char session_key[32] __attribute__((aligned(32)));
    uint8_t pub[DH_SIZE]   __attribute__((aligned(DH_SIZE)));
    uint8_t agree[DH_SIZE] __attribute__((aligned(DH_SIZE)));
    PAL_NUM pubsz, agreesz;
    LIB_DH_CONTEXT context;
    int ret;

    ret = lib_DhInit(&context);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH Init failed: %d\n", ret);
        goto out_no_final;
    }

    pubsz = sizeof pub;
    ret = lib_DhCreatePublic(&context, pub, &pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH CreatePublic failed: %d\n", ret);
        goto out;
    }

    assert(pubsz > 0 && pubsz <= DH_SIZE);
    if (pubsz < DH_SIZE) {
        /* Insert leading zero bytes if necessary. These values are big-
         * endian, so we either need to know the length of the bignum or
         * zero-pad at the beginning instead of the end. This code chooses
         * to do the latter. */
        memmove(pub + (DH_SIZE - pubsz), pub, pubsz);
        memset(pub, 0, DH_SIZE - pubsz);
    }

    ret = write(stream, 0, DH_SIZE, pub);
    if (ret != DH_SIZE) {
        SGX_DBG(DBG_S, "Key Exchange: write failed: %d\n", ret);
        goto out;
    }

    ret = read(stream, 0, DH_SIZE, pub);
    if (ret != DH_SIZE) {
        SGX_DBG(DBG_S, "Key Exchange: read failed: %d\n", ret);
        goto out;
    }

    agreesz = sizeof agree;
    ret = lib_DhCalcSecret(&context, pub, DH_SIZE, agree, &agreesz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH CalcSecret failed: %d\n", ret);
        goto out;
    }

    assert(agreesz > 0 && agreesz <= sizeof agree);
    // TODO(security): use a real KDF
    memset(session_key, 0, sizeof(session_key));
    for (int i = 0 ; i < agreesz ; i++)
        session_key[i % sizeof(session_key)] ^= agree[i];

    SGX_DBG(DBG_S, "key exchange: (%p) %s\n", session_key, hex2str(session_key));

    if (keyptr)
        memcpy(keyptr, session_key, sizeof(PAL_SESSION_KEY));

    ret = 0;
out:
    lib_DhFinal(&context);
out_no_final:
    return ret;
}

struct attestation_request {
    sgx_arch_hash_t       mrenclave;
    sgx_arch_attributes_t attributes;
};

struct attestation {
    sgx_arch_hash_t       mrenclave;
    sgx_arch_attributes_t attributes;
    sgx_arch_report_t     report;
};

int _DkStreamAttestationRequest (PAL_HANDLE stream, void * data,
                                 handle_read_t read, handle_write_t write,
                                 check_mrenclave_t check_mrenclave,
                                 void * check_param)
{
    struct attestation_request req;
    struct attestation att;
    int bytes, ret;

    memcpy(req.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&req.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation request ... (mrenclave = %s)\n",\
            hex2str(req.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(req) ; bytes += ret) {
        ret = write(stream, 0, sizeof(req) - bytes, ((void *) &req) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: write failed: %d\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = read(stream, 0, sizeof(att) - bytes, ((void *) &att) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: read failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation (mrenclave = %s)\n",
            hex2str(att.mrenclave));

    ret = sgx_verify_report(&att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: verify failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Remote attestation not signed by SGX!\n");
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    ret = check_mrenclave(&att.report.mrenclave, &att.report.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed encalve (mrenclave = %s)\n",
               hex2str(att.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Remote attestation succeed!\n");

    ret = sgx_get_report(&att.mrenclave, &att.attributes, data, &att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: get report failed: %d\n", ret);
        goto out;
    }

    memcpy(att.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&att.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation ... (mrenclave = %s)\n",
            hex2str(att.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = write(stream, 0, sizeof(att) - bytes, ((void *) &att) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: write failed: %d\n", ret);
            goto out;
        }
    }

    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

int _DkStreamAttestationRespond (PAL_HANDLE stream, void * data,
                                 handle_read_t read, handle_write_t write,
                                 check_mrenclave_t check_mrenclave,
                                 void * check_param)
{
    struct attestation_request req;
    struct attestation att;
    int bytes, ret;

    for (bytes = 0, ret = 0 ; bytes < sizeof(req) ; bytes += ret) {
        ret = read(stream, 0, sizeof(req) - bytes, ((void *) &req) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: read failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation request ... (mrenclave = %s)\n",
            hex2str(req.mrenclave));

    ret = sgx_get_report(&req.mrenclave, &req.attributes, data, &att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: get report failed: %d\n", ret);
        goto out;
    }

    memcpy(att.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&att.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation ... (mrenclave = %s)\n",
            hex2str(att.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = write(stream, 0, sizeof(att) - bytes, ((void *) &att) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: write failed: %d\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = read(stream, 0, sizeof(att) - bytes, ((void *) &att) + bytes);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: read again failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation (mrenclave = %s)\n",
            hex2str(att.mrenclave));

    ret = sgx_verify_report(&att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: verify failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Remote attestation not signed by SGX!\n");
        goto out;
    }

    ret = check_mrenclave(&att.report.mrenclave, &att.report.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed encalve (mrenclave = %s)\n",
                hex2str(att.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Remote attestation succeed!\n");
    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

static int stream_context_alloc_buffer (struct pal_stream_context * ctx,
                                        uint64_t size)
{
    size = ALLOC_ALIGNUP(size);

    if (size <= ctx->bufsize)
        return 0;

    uint64_t newsize = ctx->bufsize ? : size;
    while (newsize < size)
        newsize *= 2;

    void * newbuf = NULL;
    int ret = ocall_alloc_untrusted(newsize, &newbuf);
    if (ret < 0)
        return ret;

    if (ctx->bufoffset)
        memcpy(newbuf, ctx->buf, ctx->bufoffset);

    if (ctx->buf)
        ocall_unmap_untrusted(ctx->buf, ctx->bufsize);

    ctx->buf = newbuf;
    ctx->bufsize = newsize;
    return 0;
}

int _DkStreamSecureInit (PAL_SESSION_KEY * key, unsigned which,
                         PAL_SEC_CONTEXT ** context)
{
    PAL_SEC_CONTEXT * sec_ctx = malloc(sizeof(PAL_SEC_CONTEXT));
    int ret;

    if (!sec_ctx)
        return -PAL_ERROR_NOMEM;

    memset(sec_ctx, 0, sizeof(PAL_SEC_CONTEXT));

    if ((ret = lib_AESGCMInit(&sec_ctx->ctxi.ctx,  (uint8_t *) key,
                              sizeof(*key))) < 0)
        return ret;

    if ((ret = lib_AESGCMInit(&sec_ctx->ctxo.ctx, (uint8_t *) key,
                              sizeof(*key))) < 0)
        return ret;

    memcpy(&sec_ctx->key, key, sizeof(*key));

    /* use part of the key as salt for now (not secure!) */
    memcpy(&sec_ctx->ctxi.iv.salt, key, sizeof(sec_ctx->ctxi.iv.salt));
    memcpy(&sec_ctx->ctxo.iv.salt, key, sizeof(sec_ctx->ctxo.iv.salt));

    /* flip the first bit of the receiption epoch of the server and the sender
     * epoch of the client */
    if (which == PAL_STREAM_SERVER)
        sec_ctx->ctxi.hdr.epoch |= SERVER_SIDE_EPOCH;
    if (which == PAL_STREAM_CLIENT)
        sec_ctx->ctxo.hdr.epoch |= SERVER_SIDE_EPOCH;

    *context = sec_ctx;
    return 0;
}

int _DkStreamSecureMigrate (PAL_SEC_CONTEXT * input, PAL_SEC_CONTEXT ** context)
{
    PAL_SEC_CONTEXT * sec_ctx = malloc(sizeof(PAL_SEC_CONTEXT));
    int ret;

    if (!sec_ctx)
        return -PAL_ERROR_NOMEM;

    memcpy(sec_ctx, input, sizeof(PAL_SEC_CONTEXT));

    if ((ret = lib_AESGCMInit(&sec_ctx->ctxi.ctx, (uint8_t *) &sec_ctx->key,
                              sizeof(sec_ctx->key))) < 0)
        return ret;

    if ((ret = lib_AESGCMInit(&sec_ctx->ctxo.ctx, (uint8_t *) &sec_ctx->key,
                              sizeof(sec_ctx->key))) < 0)
        return ret;

    sec_ctx->ctxi.buf = sec_ctx->ctxo.buf = NULL;
    sec_ctx->ctxi.bufsize = sec_ctx->ctxo.bufsize = 0;
    sec_ctx->ctxi.bufoffset = sec_ctx->ctxo.bufoffset = 0;
    *context = sec_ctx;
    return 0;
}

int _DkStreamSecureFree (PAL_SEC_CONTEXT * context)
{
    lib_AESGCMFree(&context->ctxi.ctx);
    lib_AESGCMFree(&context->ctxo.ctx);
    free(context);
    return 0;
}

int _DkStreamSecureRead (PAL_HANDLE handle,
                         PAL_SEC_CONTEXT * sec_ctx, handle_read_t read,
                         int offset, int count, void * buffer)
{
    struct pal_stream_context * ctx = &sec_ctx->ctxi;
    int ret;

    ret = stream_context_alloc_buffer(ctx, PAL_SEC_INIT_BUFSIZE);
    if (ret < 0)
        return ret;

    if (ctx->bufoffset < sizeof(ctx->hdr)) {
        ret = read(handle, offset, ctx->bufsize - ctx->bufoffset,
                   ctx->buf + ctx->bufoffset);

        if (ret <= 0)
            return ret;

        ctx->bufoffset += ret;
        if (ctx->bufoffset < sizeof(ctx->hdr))
            return -PAL_ERROR_TRYAGAIN;
    }

    memcpy(&ctx->hdr, ctx->buf, sizeof(ctx->hdr));

    stream_context_alloc_buffer(ctx, ctx->hdr.msg_len);
    if (ctx->bufsize < ctx->hdr.msg_len)
        return -PAL_ERROR_NOMEM;


    if (ctx->bufoffset < ctx->hdr.msg_len) {
        ret = read(handle, offset, ctx->bufsize - ctx->bufoffset,
                   ctx->buf + ctx->bufoffset);

        if (ret <= 0)
            return ret;

        ctx->bufoffset += ret;
        if (ctx->bufoffset < ctx->hdr.msg_len)
            return -PAL_ERROR_TRYAGAIN;
    }

    int msg_len = ctx->hdr.msg_len - sizeof(ctx->hdr);
    int enc_len = msg_len - GCM_TAG_SIZE;
    uint8_t * input = ctx->buf + sizeof(ctx->hdr);
    uint8_t * tag = input + enc_len;

    SGX_DBG(DBG_O, "[DEC %08lx] Received %d bytes from the stream\n",
            ctx->hdr.epoch, ctx->bufoffset);

    ctx->iv.nonce = ctx->hdr.epoch;

    SGX_DBG(DBG_O, "[DEC %08lx] Header = %s IV = %s\n",
            ctx->hdr.epoch,
            __hex2str(&ctx->hdr, sizeof(ctx->hdr)),
            __hex2str(&ctx->iv,  sizeof(ctx->iv)));

    if (enc_len > 16)
        SGX_DBG(DBG_O, "[DEC %08lx] Enc = %s ... (%d bytes) Tag = %s\n",
                ctx->hdr.epoch, __hex2str(input, 16), enc_len,
                __hex2str(tag, GCM_TAG_SIZE));
    else
        SGX_DBG(DBG_O, "[DEC %08lx] Enc = %s Tag = %s\n",
                ctx->hdr.epoch, __hex2str(input, enc_len),
                __hex2str(tag, GCM_TAG_SIZE));

    uint64_t dec_len = count;
    ret = lib_AESGCMAuthDecrypt(&ctx->ctx,
                                (const uint8_t *) &ctx->iv,
                                sizeof(ctx->iv),
                                (const uint8_t *) &ctx->hdr,
                                sizeof(ctx->hdr),
                                input, enc_len,
                                (uint8_t *) buffer, &dec_len,
                                tag, GCM_TAG_SIZE);

    if (ret < 0)
        SGX_DBG(DBG_O, "[DEC %08lx] authentication failed\n", ctx->hdr.epoch);

    ctx->hdr.epoch = (ctx->hdr.epoch & SERVER_SIDE_EPOCH)|
                     ((ctx->hdr.epoch + 1) & ~SERVER_SIDE_EPOCH);
    ctx->bufoffset -= ctx->hdr.msg_len;
    memmove(ctx->buf, ctx->buf + ctx->hdr.msg_len, ctx->bufoffset);

out:
    return ret < 0 ? ret : dec_len;
}

int _DkStreamSecureWrite (PAL_HANDLE handle,
                          PAL_SEC_CONTEXT * sec_ctx, handle_write_t write,
                          int offset, int count, const void * buffer)
{
    struct pal_stream_context * ctx = &sec_ctx->ctxo;
    uint8_t tag[GCM_TAG_SIZE];
    int ret;

    int msg_len = sizeof(ctx->hdr) + count + sizeof(tag);

    ctx->hdr.msg_len = msg_len;
    ctx->iv.nonce = ctx->hdr.epoch;

    SGX_DBG(DBG_O, "[ENC %08lx] Header = %s IV = %s\n",
            ctx->hdr.epoch,
            __hex2str(&ctx->hdr, sizeof(ctx->hdr)),
            __hex2str(&ctx->iv,  sizeof(ctx->iv)));

    ret = stream_context_alloc_buffer(ctx,
                                      msg_len > PAL_SEC_INIT_BUFSIZE ?
                                      msg_len : PAL_SEC_INIT_BUFSIZE);
    if (ret < 0)
        return ret;

    uint8_t * output = ctx->buf;
    uint8_t * enc = output + sizeof(ctx->hdr);
    uint64_t enc_len = 0;
    memcpy(output, &ctx->hdr, sizeof(ctx->hdr));

    ret = lib_AESGCMAuthEncrypt(&ctx->ctx,
                                (const uint8_t *) &ctx->iv,
                                sizeof(ctx->iv),
                                (const uint8_t *) &ctx->hdr,
                                sizeof(ctx->hdr),
                                (const uint8_t *) buffer, count,
                                (uint8_t *) enc, &enc_len,
                                (uint8_t *) &tag, sizeof(tag));

    if (ret < 0)
        goto out;

    assert(enc_len > 0);

    if (enc_len > 16)
        SGX_DBG(DBG_O, "[ENC %08lx] Enc = %s ... (%d bytes) Tag = %s\n",
                ctx->hdr.epoch, __hex2str(enc, 16), enc_len, hex2str(tag));
    else
        SGX_DBG(DBG_O, "[ENC %08lx] Enc = %s Tag = %s\n",
                ctx->hdr.epoch, __hex2str(enc, enc_len), hex2str(tag));

    SGX_DBG(DBG_O, "[ENC %08lx] Sending %d bytes to the stream\n",
            ctx->hdr.epoch, msg_len);

    memcpy(enc + enc_len, &tag, sizeof(tag));

    int sent = 0;
    while (sent < msg_len) {
        ret = write(handle, 0, msg_len - sent, output + sent);
        if (ret < 0)
            goto out;

        sent += ret;
    }

    ctx->hdr.epoch = (ctx->hdr.epoch & SERVER_SIDE_EPOCH)|
                     ((ctx->hdr.epoch + 1) & ~SERVER_SIDE_EPOCH);

out:
    return ret < 0 ? ret : count;
}
