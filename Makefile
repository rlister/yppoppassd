CC = gcc
CFLAGS = -g
LFLAGS = -g

EXE = yppoppassd
OBJECTS = yppoppassd.o yppasswd_xdr.o
LIBS = -lcrypt -lnsl

$(EXE): $(OBJECTS)
	$(CC) -o $(EXE) $(LFLAGS) $(OBJECTS) $(LIBS)

clean:
	rm -f *.o *~* core Makefile.new Makefile.bak $(EXE)
