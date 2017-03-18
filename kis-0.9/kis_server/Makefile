MODDEFS = -D__KERNEL__ -DMODULE -DMODVERSIONS -D__KERNEL_SYSCALLS__
CFLAGS = -Wall -O2
MODCFLAGS = -Wstrict-prototypes -fomit-frame-pointer -pipe -fno-strength-reduce -malign-loops=2 -malign-jumps=2 -malign-functions=2 -include /usr/src/linux/include/linux/modversions.h -I/usr/src/linux/include

all:		kis
		sync

kis:		
		cat DISCLAIMER
		gcc $(CFLAGS) $(MODCFLAGS) -c kis.c -o kis.o $(MODDEFS)
		gcc -o builder builder.c
		./builder
		cat kis.o >> kis

clean:		
		rm -f kis kis.o loader builder
