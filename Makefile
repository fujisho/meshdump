CFLAGS=-g

meshdump: main.o
	$(CC) -o meshdump main.o -lpcap
clean:
	$(RM) meshdump *.o *~