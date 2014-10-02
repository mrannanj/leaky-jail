#include <stdio.h>

int main() {
	long i, x=0;
	for (i = 0; i < 10000000000; ++i) x += i;
	printf("ebin %ld\n", x);
	return 0;
}
