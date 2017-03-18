/* 
 *Compile:
 *gcc - O2 - c get_sys_call_addr.c - I / usr / src / linux / include - fomit -frame - pointer 
 * # Install:
 * # /sbin/insmod get_sys_call_addr.o
 **After install, copy / proc / syscall to some safe place.When you suspect * LKM was installed, compare the / proc / syscall to your original copy.If * they are different, probably LKM was installed. * *The format of / proc / syscall is:
 *sys_call_index sys_call_addr 
 */
#define __KERNEL__
#define MODULE
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/config.h>
#include <linux/smp_lock.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <linux/sys.h>
#include <sys/syscall.h>	/* The list of system calls */
#include <linux/dirent.h>
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>
#include <asm/errno.h>
#define MOD_NAME "syscalls"
extern void *sys_call_table[];

/*  
 * following "read" functions are used to provide information in 
 * /proc file system 
 */
static int
read_sys_call_addr (char * buf, char ** start, off_t offset, int len, int * eof,
		      void * data){
  int i;
  if(offset > 0) return 0;
  len = sprintf (buf, "# system call addresses\n");

  for (i = 0; i < NR_syscalls; i++){
    len += sprintf (buf + len, "%3d\t%x\n", i, (void *)(sys_call_table[i]));
  }
  //len+= sprintf(buf+len, "0\t%x\n", (void *)(sys_call_table[0]));
  *start = buf;
  *eof = 1;
  return len;
}

int
init_module (void)
{
  struct proc_dir_entry * ent = create_proc_entry("syscalls", S_IFREG|S_IRUGO, &proc_root);
  if(ent == 0x0)
    return -EINVAL;
  ent->read_proc = read_sys_call_addr;
  return 0;
  // proc_register (&proc_root, &sys_call_addr);
}


void
cleanup_module (void)
{
  remove_proc_entry("syscalls", &proc_root);
  //proc_unregister (&proc_root, sys_call_addr.low_ino);
}
