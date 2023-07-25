ARCH ?= $(shell uname -m)
CROSS_COMPILE ?= 

CC	:= $(CROSS_COMPILE)gcc
LD	:= $(CROSS_COMPILE)ld
CFLAGS	?= -g -Wall -Werror
CFLAGS	+= -DARCH_$(ARCH)

all: victim spy

clean:
	rm -f victim
	rm -f spy

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) -o $@ $^