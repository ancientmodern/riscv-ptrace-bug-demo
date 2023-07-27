#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>

#define FILE_SIZE 100

void pr_perror(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	fprintf(stderr, "ERR: %s:%d: ", __FILE__, __LINE__);
	vfprintf(stderr, format, args);
	fprintf(stderr, " (errno = %d (%s))\n", errno, strerror(errno));

	va_end(args);
}

int main(int argc, char **argv)
{
	int fd;
	int ret = 0;
	char *filename = "ghost.test";

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		exit(1);
	}

	ret = ftruncate(fd, FILE_SIZE);
	if (ret) {
		pr_perror("Can't fixup file size, ret = %d", ret);
		exit(1);
	}

	printf("errno = %d (%s)\n", errno, strerror(errno));
	return 0;
}