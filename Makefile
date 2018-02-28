#
# File          : Makefile
# Description   : Build file for CMPSC497 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/opt/local/lib
#INCLUDES=-I. -I/opt/local/include
CC=gcc
#CC=afl-2.52b/afl-gcc 
CFLAGS=-c $(INCLUDES) -g -Wall 
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cmpsc497-p1
LIBS=-lcrypto -lm

#
# Project Protections

p1 : $(TARGETS)

cmpsc497-p1 : cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o
	$(LINK) $(LDFLAGS) cmpsc497-main.o cmpsc497-kvs.o cmpsc497-ssl.o cmpsc497-util.o $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGETS)

BASENAME=p1
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cmpsc497-main.c \
	    $(BASENAME)/cmpsc497-kvs.c \
	    $(BASENAME)/cmpsc497-kvs.h \
	    $(BASENAME)/cmpsc497-ssl.c \
	    $(BASENAME)/cmpsc497-ssl.h \
	    $(BASENAME)/cmpsc497-util.c \
	    $(BASENAME)/cmpsc497-util.h 


