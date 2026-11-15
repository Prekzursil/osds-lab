#include <stdio.h>

char *secret_msg = "The quieter you become, the more you are able to hear.";

int dothidden() {
	secret_msg = "True hackers see beyond what they are told... You won!";
	return 0;
}

int win() {
	puts(secret_msg);
	return 0;
}

int main() {
	char buf[30];
	scanf("%s", buf);
	return 0;
}
