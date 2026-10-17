local xterm = {}
local ffi = require("ffi")
local lastsig = 0
local bit = require("bit")

local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function _64encode(data)
    return ((data:gsub('.', function(x)
        local r, bits='', x:byte()
        for i = 8, 1, -1 do
            r = r .. (bits%2^i-bits%2^(i-1)>0 and '1' or '0')
        end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then return '' end
        local c=0
        for i = 1, 6 do
            c=c+(x:sub(i, i) == '1' and 2 ^ (6 - i) or 0)
        end
        return b:sub(c+1,c+1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

ffi.cdef([[   
   struct termios {
    unsigned int c_iflag;
    unsigned int c_oflag;
    unsigned int c_cflag;
    unsigned int c_lflag;
    unsigned char c_line;
    unsigned char c_cc[32];
    unsigned int c_ispeed;
    unsigned int c_ospeed;
   };

   typedef struct winsize {
       unsigned short ws_row;
       unsigned short ws_col;
       unsigned short ws_xpixel;
       unsigned short ws_ypixel;
   } winsize;
]])

if not pcall(ffi.new, "struct pollfd") then
  ffi.cdef [[
   struct pollfd {
     int fd;
     short events;
     short revents;
   };
  ]]
end

ffi.cdef([[
   int tcgetattr(int fd, struct termios *termios_p);
   int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
   
   typedef void (*sig)(int);
   sig signal(int signal, sig handler);

   int poll(struct pollfd *fds, unsigned long nfds, int timeout);
   int read(int fd, void *buf, size_t count);
   int usleep(int usec);
   int ioctl(int fd, unsigned long request, void *argp);
   int isatty(int fd);
   int close(int fd);
   void pause();
]])

function sighandler(sig)
  lastsig = sig
end

function xterm.initSigCapture()
  for i = 0, 64 do
    ffi.C.signal(i, sighandler)
  end
end

function xterm.fficast(...)
  return ffi.cast(...)
end

function xterm.ffinew(...)
  return ffi.new(...)
end

function xterm:setcontrolchars(fd, array)
  local termios = ffi.new("struct termios")
  ffi.C.tcgetattr(fd, termios)
  for i = 0, #array do
    if array[i] then
      termios.c_cc[i] = array[i]
    end
  end
  ffi.C.tcsetattr(fd, array.optionalactions or 0, termios)
end

function xterm:setmode(fd, modes)
  local termios = ffi.new("struct termios")
  local original = ffi.new("struct termios")
  ffi.C.tcgetattr(fd, termios)
  for _, mode in ipairs(modes) do
    termios[mode.field or "c_lflag"] = mode.flag or 0
  end
  ffi.C.tcsetattr(fd, modes.optionalactions or 0, termios)
  return original
end

function xterm:gettermios(fd)
  local termios = ffi.new("struct termios")
  ffi.C.tcgetattr(fd or 0, termios)
  return termios
end

function xterm:mouse(timeout, buf)
  local buttons = {
    [0]  = "left",
    [1]  = "middle",
    [2]  = "right",
    [32] = "left_drag",
    [33] = "middle_drag",
    [34] = "right_drag",
    [35] = "move",
    [64] = "scroll_up",
    [65] = "scroll_down",
  }

  local fd = ffi.new("struct pollfd", { fd = 0, events = 1 })
  local buff = ffi.new("char[?]", buf or 1024)
  local ret = ffi.C.poll(fd, 1, timeout or 10)

  if ret > 0 then
    local n = ffi.C.read(0, buff, buf or 95)
    local key = ffi.string(buff, n)
    if n > 0 then
      local res = ffi.string(buff, n)

      local Type, x, y, flag = res:match("<(%d+);(%d+);(%d+)([Mm])")
      local state
      if tonumber(Type) == 35 then
        state = "hover"
      elseif flag == "M" then
        state = "down"
      else
        state = "up"
      end
      return {
        type = buttons[tonumber(Type)] or "?",
        x = tonumber(x),
        y = tonumber(y),
        click = state,
        key = key,
      }
    end
  end
end

function xterm:timeoutread(timeout, buf)
  local fd = ffi.new("struct pollfd", { fd = 0, events = 1 })
  local buff = ffi.new("char[?]", buf or 1024)
  local ret = ffi.C.poll(fd, 1, timeout or 10)

  if ret > 0 then
    local n = ffi.C.read(0, buff, buf or 95)
    if n > 0 then
      local key = ffi.string(buff, n)
      return key, n
    end
  end
end

function xterm:read(bytes)
  local buf = ffi.new("char[?]", bytes or 1)
  local readed = ffi.C.read(0, buf, bytes or 1)
  return ffi.string(buf, readed), readed
end

function xterm:icannon(state)
   local termios = ffi.new("struct termios")
   ffi.C.tcgetattr(0, termios)

   if state == true then
      termios.c_lflag = bit.band(termios.c_lflag, bit.bnot(0x02))
   else
      termios.c_lflag = bit.bor(termios.c_lflag, 0x02)
   end

   ffi.C.tcsetattr(0, 0, termios)
   return termios
end

function xterm:autonewline(state)
   local termios = ffi.new("struct termios")
   ffi.C.tcgetattr(0, termios)

   if state == false then
      termios.c_oflag = bit.bor(termios.c_oflag, 0x04)
   else
      termios.c_oflag = bit.band(termios.c_oflag, bit.bnot(0x04))
   end

   ffi.C.tcsetattr(0, 0, termios)
   return termios
end

function xterm:isig(state)
   local termios = ffi.new("struct termios")
   ffi.C.tcgetattr(0, termios)

   if state == true then
      termios.c_lflag = bit.bor(termios.c_lflag, 0x01)
   else
      termios.c_lflag = bit.band(termios.c_lflag, bit.bnot(0x01))
   end

   ffi.C.tcsetattr(0, 0, termios)
   return termios
end

function xterm:echo(state)
   local termios = ffi.new("struct termios")
   ffi.C.tcgetattr(0, termios)

   if state == false then
      termios.c_lflag = bit.band(termios.c_lflag, bit.bnot(0x08))
   else
      termios.c_lflag = bit.bor(termios.c_lflag, 0x08)
   end

   ffi.C.tcsetattr(0, 0, termios)
   return termios
end

function xterm:init()
   os.execute("stty raw -echo")
end

function xterm:reset()
  io.write("\27[?1003l")
  io.write("\27[?1049l")
  io.flush()
  os.execute("stty sane")
  io.flush()
end

function xterm.thrpause()
  ffi.C.pause()
end

function xterm:mouseinit()
  io.write("\27[?1006h")
  io.write("\27[?1002h")
  io.flush()
end

function xterm:setsignal(sig, f)
  ffi.C.signal(sig, ffi.cast("sig", f))
end

function xterm:text(text, x, y, r, g, b)
  local lasttext = text
  local format = string.format("\27[38;2;%s;%s;%sm%s", r or 255, g or 255, b or 255, tostring(lasttext))
  io.write(string.format("\27[%s;%sH%s\27[0m", y or 1, x or 1, format))
  io.flush()

  return {
    text = lasttext,
    x = x or 1,
    y = y or 1,

    detectcollision = function(self, mx, my)
       if not mx and not my then return false end
       return (mx >= self.x and mx <= self.x + #lasttext - 1) and (my == self.y)
    end,

    changetext = function(self, newtext, nr, ng, nb)
      newtext = tostring(newtext)
      local old = #self.text
      lasttext = newtext
      self.text = newtext

      io.write(string.format("\27[%s;%sH%s", self.y, self.x, string.rep(" ", old)))
      local format = string.format("\27[38;2;%s;%s;%sm%s\27[0m", nr or 255, ng or 255, nb or 255, tostring(lasttext))
      io.write(string.format("\27[%s;%sH%s", self.y, self.x, format))
      io.flush()
      self.text = newtext
    end,

    move = function(self, txt, nx, ny)
       txt = tostring(txt)
       local currtextlen = #self.text
       io.write(string.format("\27[%s;%sH%s", self.y, self.x, string.rep(" ", currtextlen)))
       io.flush()
       io.write(string.format("\27[%s;%sH%s", ny, nx, txt))
       io.flush()
       self.x = nx
       self.y = ny
       self.text = txt
    end
  }
end

function xterm:movecursor(x, y)
  io.write(string.format("\27[%s;%sH", y, x))
  io.flush()
end

function xterm:mousereset()
  io.write("\27[?1003l")
  io.flush()
end

function xterm.usleep(int)
  ffi.C.usleep(tonumber(int))
end

function xterm:mousehover(state)
  if state then
    io.write("\27[?1003h")
    io.flush()
  else
    io.write("\27[?1003l")
    io.flush()
  end
end

function xterm:clear()
  io.write("\27[H\27[2J\27[3J")
  io.flush()
end

setmetatable(xterm, {
  __index = function(t, k)
    if k == "currentline" then
      io.write("\27[6n")
      io.flush()
      local row, col = xterm:read(1048):match("(%d+);(%d+)R")
      return {
        x = tonumber(col),
        y = tonumber(row)
      }
    end
    if k == "sizes" then
      local winsize = ffi.new("winsize")
      local result = ffi.C.ioctl(0, 0x5413, winsize)
      if result == 0 then
        return winsize
      end
    end
    if k == "last" then
      return {
        signal = lastsig,
        byte = function(bytes)
          return string.byte(xterm:read(bytes or 1))
        end
      }
    end
  end
})

function xterm:alternativeScr(state)
   if state then
      io.write("\27[?1049h")
   else
      io.write("\27[?1049l")
   end
   io.flush()
end

function xterm:resize(x, y)
   io.write("\27[8;" .. tonumber(x) .. ";" .. tonumber(y) .. "t")
end

function xterm:toclipboard(text)
 local b64 = _64encode(tostring(text))
 io.write("\27]52;c;" .. b64 .. "\a")
 io.flush()
end

function xterm:settitle(text)
 io.write("\27]0;" .. tostring(text) .. "\a")
 io.flush()
end

function xterm:RGBbackground(r, g, b)
  return string.format("\27[48;2;%s;%s;%sm", r, g, b)
end

function xterm:coloreset()
  return "\27[0m"
end

function xterm:RGBColor(r, g, b)
  return string.format("\27[38;2;%s;%s;%sm", r, g, b)
end

function xterm:bell()
  io.write("\a")
  io.flush()
end

function xterm:hyperlink(url, text)
  local OSC = "\27]"
  local ST = "\27\\"
  return string.format("%s8;;%s%s%s%s8;;%s", OSC, url, ST, text, OSC, ST)
end

function xterm:istty(fd)
  return ffi.C.isatty(fd or 1) == 1
end

function xterm:close(fd)
  return ffi.C.close(fd) == 0
end

function xterm:warn(text)
  io.stderr:write("\27[43m\27[30m" .. tostring(text) .. "\27[0m")
  io.flush()
end

function xterm:error(text)
  io.stderr:write("\27[41m\27[30m" .. tostring(text) .. "\27[0m")
  io.flush()
end

function xterm:success(text)
  io.write("\27[42m\27[30m" .. tostring(text) .. "\27[0m")
  io.flush()
end

function xterm:hidecursor(state)
  if state then
     io.write("\27[?25l")
     io.flush()
  else
     io.write("\27[?25h")
     io.flush()
  end
end

function xterm:checkbox(y, x, t)
    local toggle = false
    local checkboxtxt = xterm:text("[ ]", x, y, 200, 200, 200)

    return {
        update = function(mouse)
            if mouse then
                if checkboxtxt:detectcollision(mouse.x, mouse.y) and mouse.click == "down" and mouse.type == "left" then
                   toggle = not toggle
                end
            end

            if toggle then
                checkboxtxt:changetext("[#]", 0, (t.checkedG or 200), 0)
            else
                checkboxtxt:changetext("[ ]", (t.nocheckedR or 200), (t.nocheckedG or 200), (t.nocheckedB or 200))
            end

            return toggle, checkboxtxt
        end
    }
end

function xterm:clearline()
  io.write("\r\27[2K")
  io.flush()
end

function xterm:saveCursor()
  io.write("\27[s"); io.flush()
end

function xterm:restoreCursor()
  io.write("\27[u"); io.flush()
end

function xterm:up(steps)
    io.write("\27[" .. steps .. "A"); io.flush()
end

function xterm:down(steps)
    io.write("\27[" .. steps .. "B"); io.flush()
end

function xterm:cgo(steps)
   io.write("\27[" .. steps .. "C"); io.flush()
end

function xterm:cback(steps)
   io.write("\27[" .. steps .. "D"); io.flush()
end

function xterm:termbgcolor(RRRR, GGGG, BBBB)
  io.write(string.format("\27]11;rgb:%s/%s/%s\7", RRRR, GGGG, BBBB)); io.flush()
end

xterm.base64encoder = _64encode

return xterm
