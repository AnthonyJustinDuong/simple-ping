ping: ping.c
	gcc -Wall -g -std=gnu99 -o ping ping.c -lm

clean:
	rm ping
