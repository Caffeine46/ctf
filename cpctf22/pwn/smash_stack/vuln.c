#include <stdio.h>

void show_stack(char *buf) {
	printf("\n");
	printf("Stack Infomation\n");

	// stack
	printf("\n");
	printf("             | address        | value              |\n");
	printf(" buf       > | %p | 0x%016llx |\n", ((long long *)buf), ((long long *)buf)[0]);
	for (int i = 1; i < 4; i++) {
		printf("             | %p | 0x%016llx |\n", ((long long *)buf) + i, ((long long *)buf)[i]);
	}
	printf(" saved rsp > | %p | 0x%016llx |\n", ((long long *)buf) + 4, ((long long *)buf)[4]);
	printf(" retaddr   > | %p | 0x%016llx |\n", ((long long *)buf) + 5, ((long long *)buf)[5]);
	printf("\n");
}

void win() {
	execve("/bin/sh", NULL, NULL);
}

int vuln() {
	char buf[32] = {};
	show_stack(buf);
	printf("win: %p\n\n", win);
	gets(buf);
	show_stack(buf);
	return 0;
}

int main() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	vuln();
	return 0;
}
