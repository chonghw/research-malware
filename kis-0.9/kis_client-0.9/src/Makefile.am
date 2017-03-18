## Process this file with automake to produce Makefile.in

## Created by Anjuta - will be overwritten
## If you don't want it to overwrite it,
## 	Please disable it in the Anjtua Project configuration

INCLUDES = \
	`gtk-config --cflags`\
	 -Wall -Wimplicit -Wreturn-type -Wunused -Wswitch -Wcomment -Wuninitialized -Wparentheses -Wpointer-arith -Wmissing-prototypes\
	 -O1\
	 -g

bin_PROGRAMS = kis_client

kis_client_SOURCES = \
	callbacks.c\
	callbacks.h\
	interface.c\
	interface.h\
	main.c\
	support.c\
	support.h

kis_client_LDADD =  \
	$(GTK_LIBS)

