CC = gcc
SRCS = main.c
OBJS = chall
CFLAGS = -Wall -O0 -Wl,-z,relro,-z,now -no-pie

.PHONY: clean

$(OBJS): $(SRCS)
	$(CC) $< -o $@ $(CFLAGS)
	
clean: 
	rm $(OBJS)