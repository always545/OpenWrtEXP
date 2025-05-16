CC = gcc
static = -static
filename = res.out
PCAPATH = -lpcap
THREADPATH = -lpthread
wrt:
	$(CC) $(static) wrt.c $(PCAPATH) -o res.out

recive:
	$(CC) $(static) Recive.c $(PCAPATH) $(THREADPATH) -o rcv.out

address:
	$(CC) -c address.c -o address.o

test:
	$(CC) $(static) test.c address.c -o testot/test.ot