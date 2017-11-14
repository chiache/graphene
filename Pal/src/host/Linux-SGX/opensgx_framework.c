/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_rtld.h>
#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"

#include <asm/errno.h>

void * zero_page;

#define EPC_ADDR    0x4fffc000

typedef unsigned char epc_t[PRESET_PAGESIZE];

static inline
void * epc_to_vaddr (epc_t * epc)
{
    return epc;
}

typedef enum {
    FREE_PAGE = 0,
    SECS_PAGE,
    TCS_PAGE,
    REG_PAGE,
    RESERVED,
} epc_type_t;

typedef struct {
    int key;
    epc_type_t type;
} epc_info_t;

enum {
    ENCLS_ECREATE      = 0x00,
    ENCLS_EADD         = 0x01,
    ENCLS_EINIT        = 0x02,
    ENCLS_EREMOVE      = 0x03,
    ENCLS_EDBGRD       = 0x04,
    ENCLS_EDBGWR       = 0x05,
    ENCLS_EEXTEND      = 0x06,
    ENCLS_ELDB         = 0x07,
    ENCLS_ELDU         = 0x08,
    ENCLS_EBLOCK       = 0x09,
    ENCLS_EPA          = 0x0A,
    ENCLS_EWB          = 0x0B,
    ENCLS_ETRACK       = 0x0C,
    ENCLS_EAUG         = 0x0D,
    ENCLS_EMODPR       = 0x0E,
    ENCLS_EMODT        = 0x0F,

    // custom hypercalls
    ENCLS_OSGX_INIT      = 0x10,
    ENCLS_OSGX_PUBKEY    = 0x11,
    ENCLS_OSGX_EPCM_CLR  = 0x12,
    ENCLS_OSGX_CPUSVN    = 0x13,
    ENCLS_OSGX_STAT      = 0x14,
    ENCLS_OSGX_SET_STACK = 0x15,
};

typedef struct {
    uint32_t oeax;
    uint64_t orbx;
    uint64_t orcx;
    uint64_t ordx;
} out_regs_t;

// encls() : Execute an encls instruction
// out_regs store the output value returned from qemu
static
void encls(int leaf, uint64_t rbx, uint64_t rcx,
           uint64_t rdx, out_regs_t* out)
{
   SGX_DBG(DBG_I, "leaf=%d, rbx=0x%llx, rcx=0x%llx, rdx=0x%llx\n",
           leaf, rbx, rcx, rdx);

   out_regs_t tmp;
   asm volatile(".byte 0x0F\n\t"
                ".byte 0x01\n\t"
                ".byte 0xcf\n\t"
                :"=a"(tmp.oeax),
                 "=b"(tmp.orbx),
                 "=c"(tmp.orcx),
                 "=d"(tmp.ordx)
                :"a"((uint32_t)leaf),
                 "b"(rbx),
                 "c"(rcx),
                 "d"(rdx)
                :"memory");

    if (out != NULL) {
        *out = tmp;
    }
}

static
void ecreate(sgx_arch_pageinfo_t * pageinfo, epc_t * epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_ECREATE,
          (uint64_t)pageinfo,
          (uint64_t)epc_to_vaddr(epc),
          0x0, NULL);
}

static
int einit(uint64_t sigstruct, epc_t * secs, uint64_t einittoken)
{
    // RBX: SIGSTRUCT(In, EA)
    // RCX: SECS(In, EA)
    // RDX: EINITTOKEN(In, EA)
    // RAX: ERRORCODE(Out)
    out_regs_t out;
    encls(ENCLS_EINIT, sigstruct, (uint64_t) epc_to_vaddr(secs), einittoken,
          &out);
    return -(int)(out.oeax);
}

static
void eadd(sgx_arch_pageinfo_t * pageinfo, epc_t * epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EADD,
          (uint64_t) pageinfo,
          (uint64_t) epc_to_vaddr(epc),
          0x0, NULL);
}

static
void eextend(uint64_t pageChunk)
{
    // RCX: 256B Page Chunk to be hashed(In, EA)
    encls(ENCLS_EEXTEND, 0x0, pageChunk, 0x0, NULL);
}

#if 0
static
void encls_qemu_init(uint64_t startPage, uint64_t endPage)
{
    // Function just for initializing EPCM within QEMU
    // based on EPC address in user code
    encls(ENCLS_OSGX_INIT, startPage, endPage, 0x0, NULL);
}

static
void encls_epcm_clear(uint64_t target_epc)
{
    encls(ENCLS_OSGX_EPCM_CLR, target_epc, 0x0, 0x0, NULL);
}

static
void set_intel_pubkey(uint64_t pubKey)
{
    // Function to set CSR_INTELPUBKEYHASH
    encls(ENCLS_OSGX_PUBKEY, pubKey, 0x0, 0x0, NULL);
}

static
void set_cpusvn(uint8_t svn)
{
    // Set cpu svn.
    encls(ENCLS_OSGX_CPUSVN, svn, 0x0, 0x0, NULL);
}

static
void set_stack(uint64_t sp)
{
    // Set enclave stack pointer.
    encls(ENCLS_OSGX_SET_STACK, sp, 0x0, 0x0, NULL);
}
#endif

//
// NOTE.
//   bitmap can contain more useful info (e.g., eid, contiguous region &c)
//
static epc_t *g_epc;
static epc_info_t *g_epc_info;
static int g_num_epc;

int init_epc (int nepc)
{
    g_num_epc = nepc;

    //toward making g_num_epc configurable
    //g_epc = memalign(PAGE_SIZE, g_num_epc * sizeof(epc_t));

    g_epc = (epc_t *)INLINE_SYSCALL(mmap, 6, (void *) EPC_ADDR,
                                    g_num_epc * sizeof(epc_t),
                                    PROT_READ|PROT_WRITE,
                                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (IS_ERR_P(g_epc)) {
        SGX_DBG(DBG_E, "EPC allocation failed\n");
        return -ENOMEM;
    }

    SGX_DBG(DBG_I, "EPC address: %p\n", (void *) g_epc);

    g_epc_info = malloc(g_num_epc * sizeof(epc_info_t));
    memset(g_epc, 0, g_num_epc * sizeof(epc_t));
    memset(g_epc_info, 0, g_num_epc * sizeof(epc_info_t));
}

static
int get_epc_index(int key, epc_type_t pt)
{
    static int last = 0;
    for (int i = 0; i < g_num_epc; i++) {
        int idx = (i + last) % g_num_epc;
        if (g_epc_info[idx].key == key
            && g_epc_info[idx].type == RESERVED) {
            g_epc_info[idx].type = pt;
            return idx;
        }
    }
    return -1;
}

static
void put_epc_index(int index)
{
    assert(0 <= index && index < g_num_epc);
    assert(g_epc_info[index].type != FREE_PAGE);

    g_epc_info[index].type = FREE_PAGE;
}

epc_t * get_epc(int key, epc_type_t pt)
{
    int idx = get_epc_index(key, pt);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

epc_t * get_epc_region_beg(void)
{
    return &g_epc[0];
}

epc_t * get_epc_region_end(void)
{
    return &g_epc[g_num_epc];
}

static
const char * epc_bitmap_to_str(epc_type_t type)
{
    switch (type) {
        case FREE_PAGE: return "FREE";
        case SECS_PAGE: return "SECS";
        case TCS_PAGE : return "TCS ";
        case REG_PAGE : return "REG ";
        case RESERVED : return "RERV";
        default:
            SGX_DBG(DBG_E, "unknown epc page type (%d)\n", type);
            assert(false);
    }
}

static
int reserve_epc_index(int key)
{
    static int last = 0;
    for (int i = 0; i < g_num_epc; i++) {
        int idx = (i + last) % g_num_epc;
        if (g_epc_info[idx].type == FREE_PAGE) {
            g_epc_info[idx].key = key;
            g_epc_info[idx].type = RESERVED;
            return idx;
        }
    }
    return -1;
}

static
int alloc_epc_index_pages(int npages, int key)
{
    int beg = reserve_epc_index(key);
    if (beg == -1)
        return -1;

    // request too many pages
    if (beg + npages >= g_num_epc) {
        put_epc_index(beg);
        return -1;
    }

    // check if we have npages
    int i;
    for (i = beg + 1; i < beg + npages; i++) {
        if (g_epc_info[i].type != FREE_PAGE) {
            // restore and return
            for (int j = beg; j < i; j ++) {
                put_epc_index(i);
            }
            return -1;
        }
        g_epc_info[i].key = key;
        g_epc_info[i].type = RESERVED;
    }

    // npages epcs allocated
    return beg;
}

epc_t * alloc_epc_pages(int npages, int key)
{
    int idx = alloc_epc_index_pages(npages, key);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

epc_t * alloc_epc_page(int key)
{
    int idx = reserve_epc_index(key);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

int read_enclave_token(int token_file, sgx_arch_token_t * token)
{
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, token_file, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (stat.st_size != sizeof(sgx_arch_token_t)) {
        SGX_DBG(DBG_I, "size of token size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, token_file, token, sizeof(sgx_arch_token_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

    return 0;
}

int read_enclave_sigstruct(int sigfile, sgx_arch_sigstruct_t * sig)
{
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, sigfile, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (stat.st_size < sizeof(sgx_arch_sigstruct_t)) {
        SGX_DBG(DBG_I, "size of sigstruct size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, sigfile, sig, sizeof(sgx_arch_sigstruct_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

    return 0;
}

#define SE_LEAF    0x12

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t info[4])
{
    asm volatile("cpuid"
                 : "=a"(info[0]),
                   "=b"(info[1]),
                   "=c"(info[2]),
                   "=d"(info[3])
                 : "a"(leaf),
                   "c"(subleaf));
}

static size_t get_ssaframesize (uint64_t xfrm)
{
    uint32_t cpuinfo[4];
    uint64_t xfrm_ex;
    int xsave_size = 0;

    cpuid(SE_LEAF, 1, cpuinfo);
    xfrm_ex = ((uint64_t) cpuinfo[3] << 32) + cpuinfo[2];

    for (int i = 2; i < 64; i++)
        if ((xfrm & (1 << i)) || (xfrm_ex & (1 << i))) {
            cpuid(0xd, i, cpuinfo);
            if (cpuinfo[0] + cpuinfo[1] > xsave_size)
                xsave_size = cpuinfo[0] + cpuinfo[1];
        }

    return ALLOC_ALIGNUP(xsave_size + sizeof(sgx_arch_gpr_t) + 1);
}

int create_enclave(sgx_arch_secs_t * secs,
                   unsigned long baseaddr,
                   unsigned long size,
                   sgx_arch_token_t * token)
{
    int flags = MAP_SHARED;

    init_epc(128*1024*1024);

    if (!zero_page) {
        zero_page = (void *)
            INLINE_SYSCALL(mmap, 6, NULL, pagesize,
                           PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS,
                           -1, 0);
        if (IS_ERR_P(zero_page))
            return -ENOMEM;
    }

    memset(secs, 0, sizeof(sgx_arch_secs_t));
    secs->size = pagesize;
    while (secs->size < size)
        secs->size <<= 1;
    secs->ssaframesize = get_ssaframesize(token->attributes.xfrm) / pagesize;
    secs->miscselect = token->miscselect_mask;
    memcpy(&secs->attributes, &token->attributes,
           sizeof(sgx_arch_attributes_t));
    memcpy(&secs->mrenclave, &token->mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&secs->mrsigner,  &token->mrsigner,  sizeof(sgx_arch_hash_t));

    if (baseaddr) {
        secs->baseaddr = (uint64_t) baseaddr & ~(secs->size - 1);
    } else {
        secs->baseaddr = ENCLAVE_HIGH_ADDRESS;
    }

    epc_t * enclave = alloc_epc_pages(secs->size / pagesize, 0);
    if (!enclave)
        return -ENOMEM;

    epc_t * secs_page = get_epc(0, SECS_PAGE);
    if (!secs_page)
        return -ENOMEM;

    sgx_arch_secinfo_t secinfo;
    memset(&secinfo, 0, sizeof(secinfo));
    secinfo.flags =
        SGX_SECINFO_FLAGS_SECS|SGX_SECINFO_FLAGS_R|SGX_SECINFO_FLAGS_W;

    sgx_arch_pageinfo_t pageinfo;
    pageinfo.srcpge  = (uint64_t) secs;
    pageinfo.secinfo = (uint64_t) &secinfo;
    pageinfo.secs    = 0;
    pageinfo.linaddr = 0;

    ecreate(&pageinfo, secs_page);

    secs->attributes.flags |= SGX_FLAGS_INITIALIZED;

    SGX_DBG(DBG_I, "enclave created:\n");
    SGX_DBG(DBG_I, "    base:         0x%016lx\n", secs->baseaddr);
    SGX_DBG(DBG_I, "    size:         0x%016lx\n", secs->size);
    SGX_DBG(DBG_I, "    attr:         0x%016lx\n", secs->attributes.flags);
    SGX_DBG(DBG_I, "    xfrm:         0x%016lx\n", secs->attributes.xfrm);
    SGX_DBG(DBG_I, "    ssaframesize: %ld\n",      secs->ssaframesize);
    SGX_DBG(DBG_I, "    isvprodid:    0x%08x\n",   secs->isvprodid);
    SGX_DBG(DBG_I, "    isvsvn:       0x%08x\n",   secs->isvsvn);

    return 0;
}

int add_pages_to_enclave(sgx_arch_secs_t * secs,
                         void * addr, void * user_addr,
                         unsigned long size,
                         enum sgx_page_type type, int prot,
                         bool skip_eextend,
                         const char * comment)
{
    sgx_arch_secinfo_t secinfo;
    int ret;

    memset(&secinfo, 0, sizeof(sgx_arch_secinfo_t));

    switch (type) {
        case SGX_PAGE_SECS:
            return -EPERM;
        case SGX_PAGE_TCS:
            secinfo.flags |= SGX_SECINFO_FLAGS_TCS;
            break;
        case SGX_PAGE_REG:
            secinfo.flags |= SGX_SECINFO_FLAGS_REG;
            if (prot & PROT_READ)
                secinfo.flags |= SGX_SECINFO_FLAGS_R;
            if (prot & PROT_WRITE)
                secinfo.flags |= SGX_SECINFO_FLAGS_W;
            if (prot & PROT_EXEC)
                secinfo.flags |= SGX_SECINFO_FLAGS_X;
            break;
    }

    char p[4] = "---";
    const char * t = (type == SGX_PAGE_TCS) ? "TCS" : "REG";
    const char * m = skip_eextend ? "" : " measured";

    if (type == SGX_PAGE_REG) {
        if (prot & PROT_READ)
            p[0] = 'R';
        if (prot & PROT_WRITE)
            p[1] = 'W';
        if (prot & PROT_EXEC)
            p[2] = 'X';
    }

    if (size == pagesize)
        SGX_DBG(DBG_I, "adding page  to enclave: %016lx [%s:%s] (%s)%s\n",
                addr, t, p, comment, m);
    else
        SGX_DBG(DBG_I, "adding pages to enclave: %016lx-%016lx [%s:%s] (%s)%s\n",
                addr, addr + size, t, p, comment, m);

    uint64_t added = 0;
    while (added < size) {
        sgx_arch_pageinfo_t pageinfo;
        epc_t * epc = get_epc(0, (uint64_t) addr + added);
        pageinfo.srcpge  = (uint64_t) (user_addr ? user_addr + added : zero_page);
        pageinfo.secinfo = (uint64_t) &secinfo;
        pageinfo.secs    = (uint64_t) epc_to_vaddr((epc_t *) secs);
        pageinfo.linaddr = (uint64_t) epc_to_vaddr(epc);

        eadd(&pageinfo, epc);

        if (!skip_eextend) {
            for (int off = 0 ; off < pagesize ; off += 256)
                eextend((uint64_t) epc_to_vaddr(epc) + off);
        }

        added += pagesize;
    }

    return 0;
}

int init_enclave(sgx_arch_secs_t * secs,
                 sgx_arch_sigstruct_t * sigstruct,
                 sgx_arch_token_t * token)
{
    unsigned long enclave_valid_addr =
                secs->baseaddr + secs->size - pagesize;

    SGX_DBG(DBG_I, "enclave initializing:\n");
    SGX_DBG(DBG_I, "    enclave id:   0x%016lx\n", enclave_valid_addr);
    SGX_DBG(DBG_I, "    enclave hash:");
    for (int i = 0 ; i < sizeof(sgx_arch_hash_t) ; i++)
        SGX_DBG(DBG_I, " %02x", sigstruct->enclave_hash[i]);
    SGX_DBG(DBG_I, "\n");

    int ret = einit((uint64_t) sigstruct, (epc_t *) secs, (uint64_t) token);

    if (ret) {
#if 0
        const char * error;
        /* DEP 3/22/17: Try to improve error messages */
        switch(ret) {
        case SGX_INVALID_SIG_STRUCT:
            error = "Invalid SIGSTRUCT";          break;
        case SGX_INVALID_ATTRIBUTE:
            error = "Invalid enclave attribute";  break;
        case SGX_INVALID_MEASUREMENT:
            error = "Invalid measurement";        break;
        case SGX_INVALID_SIGNATURE:
            error = "Invalid signature";          break;
        case SGX_INVALID_LICENSE:
            error = "Invalid EINIT token";        break;
        case SGX_INVALID_CPUSVN:
            error = "Invalid CPU SVN";            break;
        default:
            error = "Unknown reason";             break;
        }
#endif
        SGX_DBG(DBG_I, "enclave EINIT failed - %d\n", ret);
        return -EPERM;
    }

    return 0;
}

int destroy_enclave(void * base_addr, size_t length)
{
    SGX_DBG(DBG_I, "destroying enclave...\n");
    /* XXX: do nothing right now */
    return 0;
}
