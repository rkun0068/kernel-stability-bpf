/* Executor stand-in: hog GB holds GB of anonymous memory, touched once;
 * hog GB churn allocates, touches and frees GB in a loop. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
	size_t len = (size_t)(atof(argc > 1 ? argv[1] : "1") * (1 << 30));
	int churn = argc > 2 && !strcmp(argv[2], "churn");
	char *p;

	do {
		p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			return 1;
		memset(p, 1, len);
		if (churn)
			munmap(p, len);
	} while (churn);
	for (;;)
		pause();
}
