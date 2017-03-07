
CC = gcc
CFLAGS = -Wall

aes : aes.o
	$(CC) $^ $(CFLAGS) -o $@

aes.o : aes.c
	$(CC) $(CFLAGS) -c $< -o $@

desl : desl.o
	$(CC) $^ $(CFLAGS) -o $@

desl.o : desl.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
	rm -f aes
	rm -f desl
