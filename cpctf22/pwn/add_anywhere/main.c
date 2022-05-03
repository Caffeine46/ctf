#include <stdio.h>
#include <stdlib.h>

void win(){
  system("cat /home/user/flag");
}

int main(){
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  void *addr = NULL;
  short num = 0;
  char comment[20];

  puts("You can add a little value to any addr!");
  printf("addr> ");
  scanf("%p",&addr);
  printf("val> ");
  scanf("%hd",&num);

  * (short *)addr += num;

  puts("Any comment?");
  scanf("%28s",comment);

  return 0;
}