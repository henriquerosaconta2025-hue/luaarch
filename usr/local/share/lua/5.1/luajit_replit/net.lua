local ffi = require("ffi")
local m = {}
local bit = require("bit")

if not pcall(ffi.new, "struct in_addr") then
  ffi.cdef([[
  struct in_addr {
   uint32_t s_addr;
  };
  ]])
end

if not pcall(ffi.new, "struct pollfd") then
  ffi.cdef([[
  struct pollfd {
   int fd;
   short events;
   short revents;
  };
  ]])
end

if not pcall(ffi.new, "struct sockaddr_in") then
  ffi.cdef([[
  struct sockaddr_in {
   uint16_t sin_family;
   uint16_t sin_port;
   struct in_addr sin_addr;
   char sin_zero[8];
  };
  ]])
end

if not pcall(ffi.new, "struct hostent") then
  ffi.cdef([[
  struct hostent {
   char *h_name;
   char **h_aliases;
   int h_addrtype;
   int h_length;
   char **h_addr_list;
  };
  ]])
end

ffi.cdef([[
  // functions
  int fcntl(int, int, int); // varags dont work
  int socket(int, int, int);
  int connect(int, const struct sockaddr *addr, int);
  int write(int, const void*, int);
  int close(int);
  int setsockopt(int, int, int, const void*, int);
  int getsockopt(int sockfd, int level, int optname, void *optval, int *optlen);

  long int read(int, void *, unsigned long);

  int poll(struct pollfd*, int, int);

  char* inet_ntoa(struct in_addr);

  int htons(int);
  int htonl(int);
  int ntohs(int);
  int ntohl(int);

  struct hostent *gethostbyname(const char *name);
  int getnameinfo(
    const void *sa,
    unsigned int salen,
    char *host,
    unsigned int hostlen,
    char *serv,
    unsigned int servlen,
    int flags
  );

  struct timeval {
   long tv_sec;
   long tv_usec;
  };

  struct iphdr {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
  };

  struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
    uint8_t  payload[65507];
  };

  struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
  };

  int inet_addr(const char *cp);

  int accept(int sockfd, struct sockaddr *addr, int *addrlen);
  int bind(int sockfd, const struct sockaddr *addr, int addrlen);
  int listen(int sockfd, int backlog);
  int shutdown(int sockfd, int how);
  int getsockname(int sockfd, struct sockaddr *addr, int *addrlen);
  int getpeername(int sockfd, struct sockaddr *addr, int *addrlen);

  // UDP
  int sendto(int sockfd, const void *buf, int len, int flags, const struct sockaddr *dest_addr, int addrlen);
  int recvfrom(int sockfd, void *buf, int len, int flags, struct sockaddr *src_addr, int *addrlen);
  const char* strerror(int);

  struct addrinfo {
    int                 ai_flags;
    int                 ai_family;
    int                 ai_socktype;
    int                 ai_protocol;
    size_t              ai_addrlen;
    struct sockaddr_in *ai_addr;
    char               *ai_canonname;
    struct addrinfo    *ai_next;
  };

  int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);

  const char *inet_ntop(int af, const void *src, char *dst, size_t size);
  void freeaddrinfo(struct addrinfo *res);

  int clock_gettime(int clk_id, struct timeval *tp);
]])

local c = ffi.C
local fstring = ffi.string

function m.geterror()
  return ffi.errno()
end

function m.geterrorstr(err)
   return fstring(c.strerror(err or ffi.errno()))
end

function m.nanotime()
    local ts = ffi.new("struct timeval")
    ffi.C.clock_gettime(4, ts)

    return tonumber(ts.tv_sec) * 1000000000
         + tonumber(ts.tv_usec)
end

function m.settimeoutv2(t)
  local fd = t.fd
  local vms = ffi.new("struct timeval")
  vms.tv_sec = t.secReadtimeo
  vms.tv_usec = t.usecReadtimeo

  c.setsockopt(fd, 1, 20, vms, ffi.sizeof(vms))
  vms.tv_sec = t.secSendtimeo
  vms.tv_usec = t.usecSendtimeo
  c.setsockopt(fd, 1, 21, vms, ffi.sizeof(vms))
  local tcpms = ffi.new("unsigned int[1]", t.msAcktimeo)
  c.setsockopt(fd, 6, 20, tcpms, ffi.sizeof(tcpms))
end

function m.poll(fd, event, timeout)
  local pfd = ffi.new("struct pollfd[1]")
  pfd[0].fd = fd
  pfd[0].events = event
  return c.poll(pfd, 1, timeout), pfd
end

function m.ipresolve(ip)
    local sa = ffi.new("uint8_t[16]")

    ffi.cast("unsigned short*", sa)[0] = 2
    ffi.cast("unsigned short*", sa)[1] = 0
    ffi.cast("unsigned int*", sa + 4)[0] = c.inet_addr(ip)

    local host = ffi.new("char[1024]")
    local res = c.getnameinfo(
        sa,
        16,
        host,
        1024,
        nil,
        0,
        4
    )

    if res ~= 0 then
        return nil
    end

    return ffi.string(host), res
end


function m.decodeUrl(URL)
  local method = URL:match("[^://]+")
  local pureurl = URL:match("://[^/]+")
  local path = URL:match("://[^/]+(/.*)")
  local port = URL:match(":(%d+)")
  return {
    method = method,
    url = pureurl and pureurl:gsub("://", "") or pureurl,
    path = path,
    port = port
  }
end

function m.dresolve(name, index)
    local res = ffi.new("struct addrinfo*[1]")
    local hints = ffi.new("struct addrinfo")
    hints.ai_family = 2

    local ret = c.getaddrinfo(name, nil, hints, res)
    if ret ~= 0 then return nil end

    local node = res[0]
    local i = 0
    local target = index or 0

    while node ~= nil and i < target do
        node = node.ai_next
        i = i + 1
    end

    if node == nil then
        c.freeaddrinfo(res[0])
        return "NULL"
    end

    local buf = ffi.new("char[16]")
    local addr = node.ai_addr
    local success = c.inet_ntop(2, addr.sin_addr, buf, 16)

    c.freeaddrinfo(res[0])

    if success ~= nil then
        return fstring(buf)
    else
        return nil
    end
end


function m.parse(httptext)
  if not httptext then return {} end
  local result = {}
  local headers = {}

  result.version, result.status, result.statustext = httptext:match("^(%S+)%s+(%S+)%s+(%S+)")

  for camp, content in httptext:gmatch("(%S+):%s+([^\r\n]+)") do
     headers[camp:lower()] = content
  end

  result.headers = headers
  result.body = httptext:match("\r?\n\r?\n(.+)")
  return result
end

function m.parseClient(text)
  if not text then return {} end
  local method, path, version = text:match("^(%S+)%s+(%S+)%s+(%S+)")
  return {
    method = method,
    path = path,
    version = version,
  }
end

function m.isValid(fd)
  return c.fcntl(fd, 3, 0)
end

function m.isConnected(fd)
    local optval = ffi.new("int[1]")
    local optlen = ffi.new("uint32_t[1]", ffi.sizeof("int"))

    if c.getsockopt(fd, 1, 4, optval, optlen) == 0 then
        return optval[0] == 0
    end

    return false, -1
end



function m.tcp()
  local obj = {}
  local sock = c.socket(2, 1, 0)
  local mt = {}

  setmetatable(obj, mt)

  mt.__index = {
    close = function()
      c.close(sock)
    end,

    connect = function(self, ip, port)
      ip = ip or "127.0.0.1"
      port = port or 80
      if ip:match("{ip}(.+)") then
        ip = m.dresolve(ip:match("{ip}(.+)"))
        if not ip then return -1, "invalid IP" end
      end
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = c.htons(port)
      addr.sin_addr.s_addr = c.inet_addr(ip)
      local ptr = ffi.cast("struct sockaddr *", addr)
      return c.connect(sock, ptr, ffi.sizeof(addr))
    end,

    fcntl = function(self, cmd, arg)
      return c.fcntl(sock, cmd, arg)
    end,

    setsockopt = function(self, level, optname, optval)
      local opt = ffi.new("int[1]", optval)
      return c.setsockopt(sock, level, optname, opt, ffi.sizeof(opt))
    end,

    noblock = function()
      local flags = c.fcntl(sock, 3, 0)
      return c.fcntl(sock, 4, flags + 2048)
    end,

    settimeout = function(self, ms)
      local vms = ffi.new("int[1]")
      vms[0] = ms
      return c.setsockopt(sock, 6, 20, vms, ffi.sizeof(vms))
    end,

    read = function(self, len)
      local internalbuf = ffi.new("char[?]", 65536)
      local n = c.read(sock, internalbuf, len or 65536)
      if n <= 0 then return nil, tonumber(n) end
      return ffi.string(internalbuf, n)
    end,

    write = function(self, data)
      local len = #data
      local buf = ffi.new("char[?]", len)
      ffi.copy(buf, data, len)
      local n = c.write(sock, buf, len)
      if n <= 0 then return nil end
      return n
    end,

    poll = function(self, event, timeout)
      local pfd = ffi.new("struct pollfd[1]")
      pfd[0].fd = sock
      pfd[0].events = event
      local ret = c.poll(pfd, 1, timeout)
      return pfd[0], ret
    end,

    fd = function(self)
      return sock
    end,

    bind = function(self, port, ip)
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = c.htons(port)
      addr.sin_addr.s_addr = c.inet_addr(ip or "0.0.0.0")
      return c.bind(sock, ffi.cast("struct sockaddr *", addr), ffi.sizeof(addr))
    end,
    listen = function(self, backlog)
      return c.listen(sock, backlog)
    end,
    accept = function(self)
      local addr = ffi.new("struct sockaddr_in")
      local addrlen = ffi.new("int[1]", ffi.sizeof(addr))
      local fd = c.accept(sock, ffi.cast("struct sockaddr *", addr), addrlen)

      return {
        fd = fd,
        ip = fstring(c.inet_ntoa(addr.sin_addr)),
        port = c.ntohs(addr.sin_port),
        send = function(selff, data)
          if not data then return end
          return c.write(fd, tostring(data), #tostring(data))
        end,
        close = function(selff)
          return c.close(fd)
        end,
        read = function(selff, len)
          local buf = ffi.new("char[?]", len)
          local n = c.read(fd, buf, len)
          if n <= 0 then return nil, n end
          return fstring(buf, n)
        end,
        getpeer = function(selff)
          local caddr = ffi.new("struct sockaddr_in")
          local caddrlen = ffi.new("int[1]", ffi.sizeof(caddr))
          local ret = c.getpeername(fd, ffi.cast("struct sockaddr *", caddr), caddrlen)
          if ret ~= 0 then return nil end
          return fstring(c.inet_ntoa(caddr.sin_addr)), c.ntohs(caddr.sin_port)
        end,
        setpeer = function(selff, ip, port)
          local caddr = ffi.new("struct sockaddr_in")
          caddr.sin_family = 2
          caddr.sin_port = c.htons(port)
          caddr.sin_addr.s_addr = c.inet_addr(ip)
          return caddr
        end
      }
    end,
    reUseAddr = function(self)
      local opt = ffi.new("int[1]", 1)
      return c.setsockopt(sock, 1, 2, opt, ffi.sizeof(opt))
    end
  }
  return obj
end












m.api = {
  structs = {
    sockaddr_in = ffi.new("struct sockaddr_in"),
    in_addr = ffi.new("struct in_addr"),
    hostent = ffi.new("struct hostent"),
    pollfd = ffi.new("struct pollfd")
  },
  raw = ffi.C,
  ffi = ffi
}





function m.udp()
  local obj = {}
  local mt = {}
  local sock = c.socket(2, 2, 0)

  setmetatable(obj, mt)

  mt.__index = {
    close = function()
      return c.close(sock)
    end,
    sendto = function(self, data, ip, port)
      data = data or ""
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = c.htons(port or 5000)
      addr.sin_addr.s_addr = c.inet_addr(ip or "127.0.0.1")
      return c.sendto(sock, data, #data, 0, ffi.cast("struct sockaddr *", addr), ffi.sizeof(addr))
    end,
    recvfrom = function(self, len, flags)
      local buf = ffi.new("char[?]", len)
      local addr = ffi.new("struct sockaddr_in")
      local addrlen = ffi.new("int[1]", ffi.sizeof(addr))
      local n = c.recvfrom(sock, buf, len, flags or 0, ffi.cast("struct sockaddr *", addr), addrlen)
      if n <= 0 then return nil end
      return fstring(buf, n), fstring(c.inet_ntoa(addr.sin_addr)), c.ntohs(addr.sin_port)
    end,
    bind = function(self, port, ip)
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = c.htons(port)
      addr.sin_addr.s_addr = c.inet_addr(ip or "0.0.0.0")
      return c.bind(sock, ffi.cast("struct sockaddr *", addr), ffi.sizeof(addr))
    end,
    fd = function(self)
      return sock
    end,
    noblock = function()
      local flags = c.fcntl(sock, 3, 0)
      return c.fcntl(sock, 4, flags + 2048)
    end,
    settimeout = function(self, ms)
      local vms = ffi.new("int[1]")
      vms[0] = ms
      return c.setsockopt(sock, 6, 20, vms, ffi.sizeof(vms))
    end,
    reUseAddr = function(self)
      local opt = ffi.new("int[1]", 1)
      return c.setsockopt(sock, 1, 2, opt, ffi.sizeof(opt))
    end
  }
  return obj
end




function m.raw(idk, prot)
  local obj = {}
  local mt = {}

  local sock = c.socket(idk or 2, 3, prot or 255)

  setmetatable(obj, mt)

  mt.__index = {
    close = function()
      return c.close(sock)
    end,

    sendto = function(self, data, ip)
      data = data or ""
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = 0
      addr.sin_addr.s_addr = c.inet_addr(ip or "127.0.0.1")
      return c.sendto(
        sock,
        data,
        #data,
        0,
        ffi.cast("struct sockaddr *", addr),
        ffi.sizeof(addr)
      )
    end,

    sendtoraw = function(self, data, ip)
      data = data or ""
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = 0
      addr.sin_addr.s_addr = c.inet_addr(ip or "127.0.0.1")

      local buf = ffi.cast("const char*", data)

      return c.sendto(
        sock,
        buf,
        ffi.sizeof(data),
        0,
        ffi.cast("struct sockaddr *", addr),
        ffi.sizeof(addr)
      )
    end,

    sendtorawsize = function(self, data, ip, size)
      data = data or ""
      local addr = ffi.new("struct sockaddr_in")
      addr.sin_family = 2
      addr.sin_port = 0
      addr.sin_addr.s_addr = c.inet_addr(ip or "127.0.0.1")

      local buf = ffi.cast("const char*", data)

      return c.sendto(
        sock,
        buf,
        size,
        0,
        ffi.cast("struct sockaddr *", addr),
        ffi.sizeof(addr)
      )
    end,

    recvfrom = function(self, len)
      local buf = ffi.new("char[?]", len)
      local addr = ffi.new("struct sockaddr_in")
      local addrlen = ffi.new("int[1]", ffi.sizeof(addr))
      local n = c.recvfrom(
        sock,
        buf,
        len,
        0,
        ffi.cast("struct sockaddr *", addr),
        addrlen
      )
      if n <= 0 then return nil end

      return fstring(buf, n), fstring(c.inet_ntoa(addr.sin_addr)), c.ntohs(addr.sin_port)
    end,

    fd = function()
      return sock
    end,

    settimeout = function(ms)
      local vms = ffi.new("int[1]", ms)
      return c.setsockopt(sock, 6, 20, vms, ffi.sizeof(vms))
    end,

    noblock = function()
      local flags = c.fcntl(sock, 3, 0)
      return c.fcntl(sock, 4, flags + 2048)
    end,
  }

  return obj
end




function m.udppacket(t)
   local data = tostring(t.payload)
   local data_len = #data
   local packet_size = ffi.sizeof("struct iphdr") + ffi.sizeof("struct udphdr") + data_len
   local buf = ffi.new("uint8_t[?]", packet_size)
   local ip = ffi.cast("struct iphdr*", buf)
   local udp = ffi.cast("struct udphdr*", buf + ffi.sizeof("struct iphdr"))
   local payload = buf + ffi.sizeof("struct iphdr") + ffi.sizeof("struct udphdr")

   ffi.copy(payload, data, data_len)

   udp.source = ffi.C.htons(t.source)
   udp.dest   = ffi.C.htons(t.dest)
   udp.len    = ffi.C.htons(data_len + ffi.sizeof("struct udphdr"))
   udp.check  = t.udpcheck or 0

   ip.version = 4
   ip.ihl = 5
   ip.tos = t.tos or 0
   ip.tot_len = ffi.C.htons(packet_size)
   ip.id = t.id or 0
   ip.frag_off = t.fragoff or 0
   ip.ttl = t.ttl or 64
   ip.protocol = 17
   ip.check = t.ipcheck or 0
   ip.saddr = type(t.saddr) == "string" and ffi.C.inet_addr(t.saddr) or tonumber(t.saddr)
   ip.daddr = type(t.daddr) == "string" and ffi.C.inet_addr(t.daddr) or tonumber(t.daddr)
   return buf
end

function m.checksum(data, len)
    local bytes = ffi.cast("uint8_t*", data)
    local sum = 0
    local i = 0

    while i < len - 1 do
       local word = bit.lshift(bytes[i], 8) + bytes[i + 1]
       sum = sum + word
       i = i + 2
    end

    if i < len then
       sum = sum + bit.lshift(bytes[i], 8)
    end

    while bit.rshift(sum, 16) > 0 do
       sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
    end

    return bit.band(bit.bnot(sum), 0xFFFF)
end

function m.icmp(type, ip, payload, sequence, id)
   local header = ffi.new("struct icmp_header")
   local sock = m.raw(2, 1)

   header.checksum = 0
   ffi.copy(header.payload, payload, #payload)
   header.identifier = ffi.C.htons(id or 1)
   header.sequence = ffi.C.htons(sequence or 1)
   header.type = type
   header.code = 0

   header.checksum = ffi.C.htons(m.checksum(ffi.cast("uint8_t*", header), 8 + #payload))

   sock:sendtorawsize(header, m.dresolve(ip, 0), 8 + #payload)

   return sock
end

return m