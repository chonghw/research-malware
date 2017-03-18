/*
 * author_banner.c, part of the knark package
 * (c) Creed @ #hack.se 1999 <creed@sekure.net>
 *
 * This program may NOT be used in a legal way,
 * or to not cause damage of any kind.
 *
 * Eat a frog for more info.
 */


#include <stdio.h>
#include "knark.h"

void author_banner(const char *progname)
{
    fprintf(stderr,
	    "\n\t%s by Creed @ #hack.se 1999 <creed@sekure.net>
\tPort to 2.4 2001 by Cyberwinds@hotmail.com #irc.openprojects.net\n",
	    progname);
    return;
}
