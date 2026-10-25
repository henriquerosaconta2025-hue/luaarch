local ffi = require("ffi")
local system = {}

ffi.cdef [[
  struct dirent {
   unsigned long d_ino;
   unsigned long d_off;
   unsigned short d_reclen;
   unsigned char d_type;
   char d_name[256];
  };
  long telldir(void*);
  void seekdir(void* dirp, long loc);

  struct dirent* readdir(void* dir);
  void* opendir(const char* path);
  int closedir(void* dir);
  int mkdir(const char* path, int mode);
  int rmdir(const char* path);
  int unlink(const char* path);
  int rename(const char* oldpath, const char* newpath);
  int chmod(const char* path, int mode);
  int flock(int fd, int operation);
  int open(const char *pathname, int flags, int mode);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
  ssize_t close(int fd);
  ssize_t readlink(const char *path, char *buf, size_t bufsiz);
  int chdir(const char *path);
  char *getcwd(char *buf, uint64_t size);
  int access(const char *pathname, int mode);
  int symlink(const char *target, const char *linkpath);
  int link(const char *oldpath, const char *newpath);
]]

function system.dir(path)
  local dir = ffi.C.opendir(path)
  if dir == nil then return nil end

  local result = {}

  while true do
    local entry = ffi.C.readdir(dir)
    if entry == nil then break end
    table.insert(result, {file = ffi.string(entry.d_name), type = entry.d_type})
    entry = nil
  end

  return {
    lines = function(self)
        local i = 0
        return function()
            i = i + 1
            return result[i], i
        end
    end,
    close = function(self)
        ffi.C.closedir(dir)
    end,
    dir = result
  }
end

setmetatable(system, {
  __index = function(t, k)
    return ffi.C[k]
  end
})

return system