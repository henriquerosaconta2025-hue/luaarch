local lib = {}
local ffi = require("ffi")
ffi.cdef[[
    unsigned int getuid(void);
    unsigned int getgid(void);
    unsigned int geteuid(void);
    unsigned int getegid(void);
    int crypto_pwhash_str(char out[128], const char *passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit);
    int crypto_pwhash_str_verify(const char key[128], const char *passwd, unsigned long long passwdlen);
    int sodium_init(void);
]]
local sodium = ffi.load("libsodium.so.26.4.0")
sodium.sodium_init()

function lib.readfile(path)
    local f = io.open(path, "r")
    if not f then return end

    local t = {}

    while true do
        local data = f:read(4096)
        if not data then break end
        table.insert(t, data)
    end

    f:close()
    return table.concat(t)
end

function lib.verify(key, passwd)
    return sodium.crypto_pwhash_str_verify(key, passwd, #passwd)
end

function lib.getusers()
    local users = {}
    local data = lib.readfile("/etc/users")

    if data then
        for line in data:gmatch("[^\r\n]+") do
            local user, hash, useruid, usergid, usershell = line:match("(%S+)%s+(%S+)%s+(%d+)%s+(%d+)%s+(%S+)")
            if user then
                table.insert(users, {
                    name = user,
                    hash = hash,
                    uid = tonumber(useruid),
                    gid = tonumber(usergid),
                    shell = usershell,
                    check = function (passwd)
                        return lib.verify(hash, passwd) == 0
                    end
                })
            end
        end
    end
    return users
end

function lib.getuserbyuid(uid)
    local data = lib.readfile("/etc/users")

    if data then
        for line in data:gmatch("[^\r\n]+") do
            local user, hash, useruid, usergid, usershell = line:match("(%S+)%s+(%S+)%s+(%d+)%s+(%d+)%s+(%S+)")
            if tonumber(useruid) == uid then
                return {
                    name = user,
                    hash = hash,
                    uid = tonumber(useruid),
                    gid = tonumber(usergid),
                    shell = usershell,
                    check = function (passwd)
                        return lib.verify(hash, passwd) == 0
                    end
                }
            end
        end
    end

    return nil
end

function lib.generate(passwd, opslimit, memlimit)
    local out = ffi.new("char[128]")
    local ret = sodium.crypto_pwhash_str(out, passwd, #passwd, opslimit, memlimit)
    if ret == 0 then
        return ffi.string(out)
    else
        return nil
    end
end

function lib.getperms()
    return {
        gid = ffi.C.getgid(),
        uid = ffi.C.getuid(),
        egid = ffi.C.getegid(),
        euid = ffi.C.geteuid(),
    }
end

return lib