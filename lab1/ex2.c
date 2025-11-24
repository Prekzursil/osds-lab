#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {

	/* Open an executable file here */
	FILE* file = fopen("bin/dummy","r"); 
	fseek(file,0x1106,SEEK_SET);

	/* Fill in the details here! */
	long pagesz = sysconf(_SC_PAGESIZE);
	void *ptr = mmap(NULL, pagesz, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	/* Copy the bytes here */
	fread(ptr, 1, pagesz, file);

	/* This monster casts ptr to a function pointer with no args and calls it. Basically jumps to your code. */
	(*(void(*)()) ptr)();
}
