SRCS=main.cpp rule.cpp hash.cpp loken.cpp
OBJS=$(patsubst %.cpp, %.o, $(SRCS))
EXEC=scalp
CC=g++
CFLAGS=-Wall -pedantic -O3 -fstrict-aliasing -fomit-frame-pointer -finline-functions -funroll-loops -std=c++98 -march=i586 -mtune=i586 -D_REENTRANT -D_THREAD_SAFE
OFLAGS=-lxml2 -lpcrecpp -pthread
LFLAGS=-L/usr/local/lib/
INC=-I/usr/include/libxml2 -I/usr/local/include

%.o : %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(EXEC) : $(OBJS)
	$(CC) -o $(EXEC) $(OFLAGS) $(OBJS) $(LFLAGS)

.PHONY: clean
clean:
	@rm -f $(OBJS) $(EXEC)

