all: *.o
*.o: *.c
	gcc -g -Wall -I. -o hlog *.c -lpthread
clean:
	-rm -rf *.o hlog *.log
