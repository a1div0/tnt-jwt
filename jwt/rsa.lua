--- RSA bindings for Tarantool
--- Carefully adapted from https://github.com/spacewander/lua-resty-rsa

local bit = require("bit")
local ffi = require("ffi")
local C = {} --ffi.C

local band = bit.band
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local tab_concat = table.concat
local setmetatable = setmetatable


local _M = {}
local mt = { __index = _M }


local PADDING = {
    RSA_PKCS1_PADDING = 1,  -- RSA_size - 11
    RSA_SSLV23_PADDING = 2, -- RSA_size - 11
    RSA_NO_PADDING = 3,     -- RSA_size
    RSA_PKCS1_OAEP_PADDING = 4, -- RSA_size - 42
}
_M.PADDING = PADDING

local KEY_TYPE = {
    PKCS1 = "PKCS#1",
    PKCS8 = "PKCS#8",
}
_M.KEY_TYPE = KEY_TYPE

ffi.cdef[[
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
BIO_METHOD *BIO_s_mem(void);
BIO * BIO_new(BIO_METHOD *type);
int BIO_puts(BIO *bp, const char *buf);
void BIO_vfree(BIO *a);

typedef struct rsa_st RSA;
RSA *RSA_new(void);
void RSA_free(RSA *rsa);
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
RSA * PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                 void *u);
RSA * PEM_read_bio_RSAPublicKey(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u);
RSA * PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **rsa, pem_password_cb *cb,
                                void *u);

unsigned long ERR_get_error_line_data(const char **file, int *line,
                                      const char **data, int *flags);
const char * ERR_reason_error_string(unsigned long e);

typedef struct evp_pkey_st EVP_PKEY;
typedef struct engine_st ENGINE;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);

int EVP_PKEY_size(EVP_PKEY *pkey);

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);

typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;

/* EVP_MD_CTX methods for OpenSSL < 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

/* EVP_MD_CTX methods for OpenSSL >= 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const unsigned char *in, int inl);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s,
                  EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf, unsigned int siglen,
                    EVP_PKEY *pkey);
int EVP_PKEY_set1_RSA(EVP_PKEY *e, RSA *r);

const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
]]


local EVP_PKEY_ALG_CTRL = 0x1000
local EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1
local NID_rsaEncryption = 6
local EVP_PKEY_RSA = NID_rsaEncryption
local ERR_TXT_STRING = 0x02

local evp_md_ctx_new
local evp_md_ctx_free


local function ssl_err()
    local err_queue = {}
    local i = 1
    local data = ffi_new("const char*[1]")
    local flags = ffi_new("int[1]")

    while true do
        local code = C.ERR_get_error_line_data(nil, nil, data, flags)
        if code == 0 then
            break
        end

        local err = C.ERR_reason_error_string(code)
        err_queue[i] = ffi_str(err)
        i = i + 1

        if data[0] ~= nil and band(flags[0], ERR_TXT_STRING) > 0 then
            err_queue[i] = ffi_str(data[0])
            i = i + 1
        end
    end

    return nil, tab_concat(err_queue, ": ", 1, i - 1)
end

function _M.libssl_load(libssl_filename)
    C = ffi.load(libssl_filename, true)

    if not pcall(function () return C.EVP_MD_CTX_create end) then
        evp_md_ctx_new = C.EVP_MD_CTX_new
        evp_md_ctx_free = C.EVP_MD_CTX_free
    else
        evp_md_ctx_new = C.EVP_MD_CTX_create
        evp_md_ctx_free = C.EVP_MD_CTX_destroy
    end
end

function _M.new(_, opts)
    local key, read_func, is_pub, md

    opts.key_type = opts.key_type or _M.KEY_TYPE.PKCS8
    opts.padding = _M.PADDING.RSA_NO_PADDING
    opts.digest = false

    if opts.public_key then
        key = opts.public_key
        if opts.key_type == KEY_TYPE.PKCS8 then
            read_func = C.PEM_read_bio_RSA_PUBKEY
        else
            read_func = C.PEM_read_bio_RSAPublicKey
        end
        is_pub = true

    elseif opts.private_key then
        key = opts.private_key
        read_func = C.PEM_read_bio_RSAPrivateKey

    else
        return nil, "public_key or private_key not found"
    end

    local bio_method = C.BIO_s_mem()
    local bio = C.BIO_new(bio_method)
    ffi_gc(bio, C.BIO_vfree)

    local len = C.BIO_puts(bio, key)
    if len < 0 then
        return ssl_err()
    end

    local pass
    if opts.password then
        local plen = #opts.password
        pass = ffi_new("unsigned char[?]", plen + 1)
        ffi_copy(pass, opts.password, plen)
    end

    local rsa = read_func(bio, nil, nil, pass)
    if rsa == nil then
        return ssl_err()
    end
    ffi_gc(rsa, C.RSA_free)

    -- EVP_PKEY
    local pkey = C.EVP_PKEY_new()
    ffi_gc(pkey, C.EVP_PKEY_free)
    if C.EVP_PKEY_set1_RSA(pkey, rsa) == 0 then
        return ssl_err()
    end

    --EVP_PKEY_CTX
    local ctx = C.EVP_PKEY_CTX_new(pkey, nil)
    if ctx == nil then
        return ssl_err()
    end
    ffi_gc(ctx, C.EVP_PKEY_CTX_free)

    -- md_ctx init for sign or verify; if signature algorithm is seted
    if opts.algorithm == 'sha256' then
        md = C.EVP_sha256()
    elseif opts.algorithm == 'sha384' then
        md = C.EVP_sha384()
    elseif opts.algorithm == 'sha512' then
        md = C.EVP_sha512()
    else
        return nil, "Unknown message digest"
    end

    -- ctx init for encrypt or decrypt
    -- default for encrypt/decrypt if nothing is set
    if opts.padding or not opts.digest then
        local init_func = is_pub and C.EVP_PKEY_encrypt_init
                or C.EVP_PKEY_decrypt_init
        if init_func(ctx) <= 0 then
            return ssl_err()
        end

        if C.EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING,
                opts.padding or PADDING.RSA_PKCS1_PADDING, nil) <= 0 then
            return ssl_err()
        end
    end

    local size = C.EVP_PKEY_size(pkey)
    return setmetatable({
        pkey = pkey,
        size = size,
        buf = ffi_new("unsigned char[?]", size),
        _encrypt_ctx = is_pub and ctx or nil,
        _decrypt_ctx = not is_pub and ctx or nil,
        is_pub = is_pub,
        md = md,
    }, mt)
end

function _M.sign(self, str)
    if self.is_pub then
        return nil, "not inited for sign"
    end

    local md_ctx = evp_md_ctx_new()
    ffi_gc(md_ctx, evp_md_ctx_free)

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return ssl_err()
    end

    if C.EVP_DigestUpdate(md_ctx, str, #str) <= 0 then
        return ssl_err()
    end

    local buf = self.buf
    local len = ffi_new("unsigned int[1]")
    if C.EVP_SignFinal(md_ctx, self.buf, len, self.pkey) <= 0 then
        return ssl_err()
    end

    return ffi_str(buf, len[0])
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    local md_ctx = evp_md_ctx_new()
    ffi_gc(md_ctx, evp_md_ctx_free)

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return ssl_err()
    end

    if C.EVP_DigestUpdate(md_ctx, str, #str) <= 0 then
        return ssl_err()
    end

    local siglen = #sig
    local buf = siglen <= self.size and self.buf
            or ffi_new("unsigned char[?]", siglen)
    ffi_copy(buf, sig, siglen)
    if C.EVP_VerifyFinal(md_ctx, buf, siglen, self.pkey) <= 0 then
        return ssl_err()
    end

    return true
end

return _M
