
CC = gcc
CFLAGS = -Wall

aes : aes.o
	$(CC) $^ $(CFLAGS) -o $@

aes.o : aes.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
	rm -f aes


