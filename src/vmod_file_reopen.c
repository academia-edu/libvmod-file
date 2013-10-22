#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

int main() {
	int fd = shm_open("/libvmod-file-reopen-files", O_RDWR, 0);
	if( fd == -1 ) {
		perror("shm_open");
		exit(EXIT_FAILURE);
	}

	bool *shm = mmap(NULL, sizeof(bool), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if( shm == MAP_FAILED ) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	__sync_bool_compare_and_swap(shm, false, true);

	return EXIT_SUCCESS;
}
