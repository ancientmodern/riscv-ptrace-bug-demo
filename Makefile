CC	:= riscv64-unknown-linux-gnu-gcc
LD	:= riscv64-unknown-linux-gnu-ld
CFLAGS	?= -g -Wall -Werror

all: victim spy

clean:
	rm -f victim
	rm -f spy

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) -o $@ $^