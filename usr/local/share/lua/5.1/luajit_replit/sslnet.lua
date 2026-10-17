local ffi = require("ffi")
local system = {}
local bit = require("bit")

local ok, ssl = pcall(ffi.load, "libssl.so.3")
if not ok then
   ssl = ffi.load("/usr/lib/libssl.so.3")
end

ffi.cdef[[
struct ssl_st;
struct ssl_ctx_st;
struct ssl_st* SSL_new(struct ssl_ctx_st*);
struct ssl_ctx_st* SSL_CTX_new(const void* method);
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct x509_st X509;
typedef struct X509_name_st X509_NAME;

int SSL_CTX_load_verify_locations(struct ssl_ctx_st *ctx, const char *CAfile, const char *CApath);

void SSL_CTX_set_verify(void *ctx, int mode, void *callback);

const char *SSL_get_version(const struct ssl_st *s);

X509 *SSL_get1_peer_certificate(struct ssl_st *ssl);
X509_NAME *X509_get_issuer_name(const X509 *x);
X509_NAME *X509_get_subject_name(const X509 *x);

long SSL_get_verify_result(struct ssl_st *s);
char* X509_verify_cert_error_string(int);

void X509_free(X509 *x);
int X509_get_version(const X509 *x);
char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);

int RAND_bytes(unsigned char *buf, int num);
int SSL_CTX_set_default_verify_paths(struct ssl_ctx_st *ctx);

const void* TLS_method(void);

void SSL_CTX_free(struct ssl_ctx_st*);
void SSL_free(struct ssl_st*);

int SSL_set_fd(struct ssl_st*, int fd);
int SSL_connect(struct ssl_st*);
int SSL_read(struct ssl_st*, void* buf, int num);
int SSL_write(struct ssl_st*, const void* buf, int num);

long SSL_ctrl(void *ssl, int cmd, long larg, void *parg);
int SSL_accept(struct ssl_st*);
int SSL_shutdown(struct ssl_st *ssl);
int SSL_CTX_use_certificate_file(struct ssl_ctx_st*, const char*, int);
int SSL_CTX_use_PrivateKey_file(struct ssl_ctx_st*, const char*, int);
int SSL_CTX_set_alpn_protos(struct ssl_ctx_st*, const unsigned char*, unsigned int);

long SSL_CTX_set_options(void *ctx, long options);

void SSL_get0_alpn_selected(const struct ssl_st*, const unsigned char**, unsigned int*);

unsigned long ERR_get_error(void);
char* ERR_error_string(unsigned long e, char* buf);

typedef int (*alpn_cb)(struct ssl_st*, const unsigned char **out,
unsigned char *outlen,
const unsigned char *in,
unsigned int inlen,
void *arg);
int SSL_CTX_set_alpn_select_cb(struct ssl_ctx_st* ctx, alpn_cb cb, void *arg);
void SSL_CTX_set_info_callback(void *ctx, void (*cb)(const void *ssl, int where, int ret));


void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, void *ssl, void *arg);
void SSL_CTX_set_msg_callback(void *ctx, void *cb);
void SSL_CTX_set_msg_callback_arg(void *ctx, void *arg);
int SSL_CTX_set_cipher_list(struct ssl_ctx_st *ctx, const char *str);
int SSL_do_handshake(struct ssl_st *ssl);
int SSL_get_error(const struct ssl_st *ssl, int ret);
]]

-- magic n̴̫͊ủ̴̥m̵̳̃b̴͊ͅe̴̤̐r̵͙̓ś̸̫
local SNI_FLAG = 55
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11

function system.geterror()
  local err = ssl.ERR_get_error()
  local buf = ffi.new("char[?]", 120)
  ssl.ERR_error_string(err, buf)
  return ffi.string(buf)
end

function system.geterror2(sobj, ret)
  return ssl.SSL_get_error(sobj, ret)
end

system.defaultcipher = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"

function system.newctx()
  return ssl.SSL_CTX_new(ssl.TLS_method())
end

function system.newctxobj(ctx)
  return ssl.SSL_new(ctx)
end

function system.setfd(sobj, sock)
  return ssl.SSL_set_fd(sobj, sock)
end

function system.sconnect(sobj)
  if not sobj then error("missing sobj") end
  return ssl.SSL_connect(sobj)
end

function system.sread(sobj, size)
  local buffer = ffi.new("char[?]", size or 1024)
  local bytes = ssl.SSL_read(sobj, buffer, size or 1024)
  if bytes == -1 then return nil, nil end
  if bytes < 0 then return false end
  return ffi.string(buffer, bytes), bytes == 0 and "CLOSE_NOTIFY" or false
end

function system.swrite(sobj, content)
  return ssl.SSL_write(sobj, tostring(content), #content)
end

function system.sfree(sobj, ctx)
  if tonumber(sobj) ~= nil then error("sobj is a number (sfree)") end
  if tonumber(ctx) ~= nil then error("ctx is a number (sfree)") end
  if sobj then ssl.SSL_free(sobj) end
  if ctx then ssl.SSL_CTX_free(ctx) end
  sobj, ctx = nil, nil
end

function system.sni(sobj, name)
  if tonumber(sobj) ~= nil then error("sobj is a number (sni)") end
  return ssl.SSL_ctrl(sobj, SNI_FLAG, 0, ffi.cast("char *", tostring(name)))
end

function system.saccept(sobj)
  if tonumber(sobj) ~= nil then error("sobj is a number (saccept)") end
  return ssl.SSL_accept(sobj)
end

function system.certfile(ctx, filestr, pem)
  return ssl.SSL_CTX_use_certificate_file(ctx, tostring(filestr), pem or 1)
end

function system.privatekey(ctx, keystr, pem)
  if tonumber(ctx) ~= nil then error("ctx is a number (privatekey)") end
  return ssl.SSL_CTX_use_PrivateKey_file(ctx, tostring(keystr), pem or 1)
end

function system.prepare(tcp, sni)
  if tcp.fd == nil then error("tcp is not a valid tcp object (prepare)") end

  local ctx = system.newctx()
  local sobj = system.newctxobj(ctx)
  system.setfd(sobj, tcp.fd())
  system.sni(sobj, tostring(sni) or "www.google.com")
  local stat = system.sconnect(sobj)
  if stat == 1 then
    return {
      sobj = sobj,
      ctx = ctx,
      read = function(self, size)
        return system.sread(sobj, size or 2048)
      end,
      write = function(self, content)
        return system.swrite(sobj, content)
      end,
      free = function(self)
        system.sfree(sobj, ctx)
      end,
      shutdown = function(self)
        return system.sshutdown(sobj)
      end
    }
  else
    return stat
  end
end

function system.sshutdown(sobj)
  return ssl.SSL_shutdown(sobj)
end

function system.clientAlpn(ctx, str)
  return ssl.SSL_CTX_set_alpn_protos(ctx, str, #str)
end

function system.get0alpn(sobj)
  local data = ffi.new("const unsigned char *[1]")
  local len  = ffi.new("unsigned int[1]")

  ssl.SSL_get0_alpn_selected(sobj, data, len)
  if data[0] ~= nil and len[0] > 0 then
    local alpn = ffi.string(data[0], len[0])
    return alpn
  else
    return nil
  end
end

function system.serverAlpn(ctx, cbfunc, f)
  local cb = ffi.cast("alpn_cb", cbfunc)
  return ssl.SSL_CTX_set_alpn_select_cb(ctx, cb, f or nil)
end

function system.setoptions(ctx, opt)
  return ssl.SSL_CTX_set_options(ctx, opt)
end

function system.infoCallback(ctx, f)
  return ssl.SSL_CTX_set_info_callback(ctx, ffi.cast("void (*)(const void*, int, int)", f))
end





local flags = {
  { 0x0001, "SSL_CB_LOOP" },
  { 0x0002, "SSL_CB_EXIT" },
  { 0x0004, "SSL_CB_READ" },
  { 0x0008, "SSL_CB_WRITE" },
  { 0x0010, "SSL_CB_HANDSHAKE_START" },
  { 0x0020, "SSL_CB_HANDSHAKE_DONE" },
  { 0x4000, "SSL_CB_ALERT" }
}

function system.decodeInfo(where, ret)
  local parts = {}

  for _, flag in ipairs(flags) do
    if bit.band(where, flag[1]) ~= 0 then table.insert(parts, flag[2]) end
  end

  if bit.band(where, 0x4000) ~= 0 and bit.band(where, 0x0004) ~= 0 then table.insert(parts, "SSL_CB_READ_ALERT") end
  if bit.band(where, 0x4000) ~= 0 and bit.band(where, 0x0008) ~= 0 then table.insert(parts, "SSL_CB_WRITE_ALERT") end

  if ret == 1 then table.insert(parts, "SSL_SUCCESS") end
  if ret == 0 then table.insert(parts, "SSL_FAILURE") end
  if ret == -1 then table.insert(parts, "SSL_ERROR") end

  return #parts > 0 and parts or { "UNKNOWN" }
end




function system.msgCallback(ctx, f)
  ssl.SSL_CTX_set_msg_callback(ctx, ffi.cast("void (*)(int, int, int, const void*, size_t, void*, void*)", f))
end

function system.cipher(ctx, cipher)
  return ssl.SSL_CTX_set_cipher_list(ctx, tostring(cipher))
end

function system.handshakestep(sobj)
  return ffi.C.SSL_do_handshake(sobj)
end

function system.randombytes(len)
    local buf = ffi.new("unsigned char[?]", len)
    if ssl.RAND_bytes(buf, len) == 1 then
       return buf
    end
end

system.API = ssl

return system
