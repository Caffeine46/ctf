#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(){
    char buf[0x30];
    init();
    scanf("%47s", buf);
    printf(buf);
    return 0;
}