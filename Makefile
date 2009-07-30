CFLAGS=-g

meshdump: main.o
	$(CXX) -o meshdump main.o -lpcap
	
clean:
	$(RM) meshdump *.o *.dump *~
