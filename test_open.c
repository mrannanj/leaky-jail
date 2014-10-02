#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char** argv)
{
	(void)argc;
	int a = open(argv[0], O_RDONLY);
	int b = open(argv[0], O_WRONLY);
	int c = open("/dev/null", O_RDONLY);

	printf("valid: %d\n", a);
	printf("invalid: %d\n", b);
	printf("invalid: %d\n", c);
	return 0;
}
