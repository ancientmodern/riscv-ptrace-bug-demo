ARCH ?= $(shell uname -m)
CROSS_COMPILE ?= 

CC	:= $(CROSS_COMPILE)gcc
LD	:= $(CROSS_COMPILE)ld
CFLAGS	?= -g -Wall -Werror
CFLAGS	+= -DARCH_$(ARCH)

all: victim spy ghost

clean:
	rm -f victim
	rm -f spy
	rm -f ghost

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) -o $@ $^

ghost: ghost.c
	$(CC) $(CFLAGS) -o $@ $^