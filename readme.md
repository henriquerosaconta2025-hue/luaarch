Welcome to LuaArch!
 my distro LuaArch is very simple.
 it is WSL2 compatible. you can configure the /etc/wsl.conf.
 but, if you want to run it on bare metal or on QEMU, the kernel and initramfs are on /boot/.
 the build scripts are in /build/.

 try some commands:
 cat <filename>
 ldir <dir>
 rm <file> or rm -d <dir>
 mkdir <file> <perms (decimal, not octal)>
 mnt <mount> <source> <target> <filesystemtype> <mountflags> <data (opcional)> or
 mnt unmount <dir> <flags>
 