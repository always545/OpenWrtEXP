CC = gcc
static = -static
filename = res.out
PCAPATH = -lpcap
THREADPATH = -lpthread
MUSLCC = musl-gcc

INCLUDE = -I/usr/local/include

wrt:
	$(CC) $(static) wrt.c $(PCAPATH) -o res.out

recive:
	$(CC) $(static) Recive.c $(PCAPATH) $(THREADPATH) -o rcv.out

address:
	$(CC) -c address.c -o address.o

test:
	$(CC) $(static) test.c address.c -o testot/test.ot
# how to debug?
# by adding switch -g
#example : gcc filename.c -o outputname -g

#how to make on openwrt?
#gcc filename -I/usr/local/include -lpcap -o outputname