CC = gcc
static = -static
filename = res.out
PCAPATH = -lpcap
THREADPATH = -lpthread
wrt:
	$(CC) $(static) wrt.c $(PCAPATH) -o res.out

recive:
	$(CC) $(static) Recive.c $(PCAPATH) $(THREADPATH) -o rcv.out