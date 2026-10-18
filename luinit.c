#include <sys/mount.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <utmp.h>
#include <fcntl.h>

int main(int argc, char **argv) {
    printf("luinit.c inited. mounting initramfs /dev and preparing /userspace (userspace disk).\n");
    mkdir("/userspace", 0755);
    mkdir("/dev", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);

    printf("mounting /dev/vda on /userspace as EXT4. (userspace disk)\n");
    if (mount("/dev/vda", "/userspace", "ext4", 0, NULL) == -1) {
       perror("CRITICAL: could not mount /dev/vda!!!! ");
       return 1;
    }

    chroot("/userspace");
    chdir("/");

    printf("proc root changed to /userspace. also changing dir to /.\n");
    printf("mounting userspace filesystems. (dev, proc, sys)\n");

    mkdir("/dev", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mkdir("/proc", 0755);
    mount("proc", "/proc", "proc", 0, NULL);
    mkdir("/sys", 0755);
    mount("sysfs", "/sys", "sysfs", 0, NULL);

    printf("spawning daemon oninit.d (/etc/oninit).\n");

    int daemonpid = fork();

    if (daemonpid == 0) {
        execl("/etc/oninit", "oninit.d", NULL);
        exit(127);
    }

    printf("waiting oninit to finish.\n");
    waitpid(daemonpid, NULL, 0);

    printf("spawning user shell (/usr/bin/lshell).\n");

    int pid = fork();

    if (pid == 0) {
        setsid();
        int fd = open(argv[1], 2);
        login_tty(fd);
        execl("/usr/bin/lshell", "lshell", NULL);
    }

    printf("entering in waitpid loop.\n");

    while (1) {
        waitpid(-1, NULL, 0);
    }
}
