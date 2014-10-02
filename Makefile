CFLAGS := -O2

.PHONY: all clean

all:
	cc ${CFLAGS} test_open.c -o test_open
	cc ${CFLAGS} test_cpu.c -o test_cpu
	cc ${CFLAGS} ljail.c -o ljail -lseccomp
clean:
	rm -f ljail test_cpu test_open
