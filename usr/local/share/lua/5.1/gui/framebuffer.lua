local ffi = require("ffi")
local lib = {}

ffi.cdef[[
   struct fb_bitfield {
    uint32_t offset, length, msb_right;
   };

   struct fb_var_screeninfo {
    uint32_t xres, yres, xres_virtual, yres_virtual;
    uint32_t xoffset, yoffset, bits_per_pixel, grayscale;
    struct fb_bitfield red, green, blue, transp;
    uint32_t nonstd, activate;
    uint32_t height, width, accel_flags;
    uint32_t pixclock, left_margin, right_margin;
    uint32_t upper_margin, lower_margin, hsync_len, vsync_len;
    uint32_t sync, vmode, rotate, colorspace;
    uint32_t reserved[4];
   };

   int ioctl(int fd, unsigned long request, ...);
   long write(int fd, const void *buf, long count);
   int open(const char *pathname, int flags, int mode);
   uint64_t lseek(int fd, uint64_t offset, int whence);
]]

local fb = ffi.C.open("/dev/fb0", 2, 0)

function lib.formatbgrx(r, g, b, a)
    return string.char(b, g, r, a)
end

function lib.drawpixel(width, bytes, y, x, data)
    ffi.C.lseek(fb, (y * width + x) * bytes, 0)
    return ffi.C.write(fb, data, #data)
end

function lib.getinfo()
    local vinfo = ffi.new("struct fb_var_screeninfo[1]")

    if ffi.C.ioctl(fb, 0x4600, vinfo) == 0 then
        return vinfo[0]
    else
        return nil
    end
end

return lib