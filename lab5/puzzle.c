#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char find[] = "/bin/find";
const char pwd_path[] = "/bin/pwd";
const char ls_path[] = "/bin/ls";

void menu() {
	puts("1. ls\n2. pwd\n3. find\n");
}

int main() {
	char *execs[] = {ls_path, pwd_path, find};
	int choice;
	menu();
	scanf("%d", &choice);
	printf("Executing %s\n", execs[choice-1]);
	execve(execs[choice-1], NULL, NULL);
	return 0;
}
