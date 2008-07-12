SRCS=main.cpp rule.cpp hash.cpp loken.cpp
OBJS=$(patsubst %.cpp, %.o, $(SRCS))
EXEC=scalp
CC=g++
CFLAGS=-Wall -pedantic -O3 -fstrict-aliasing -std=c++98 -march=i586 -mtune=i586
OFLAGS=-lxml2 -lpcrecpp -lboost_thread
LFLAGS=-L/usr/local/lib/
INC=-I/usr/include/libxml2 -I/usr/local/include

%.o : %.cpp
	$(CC) -c $(CFLAGS) $(INC) $*.cpp -o $@

$(EXEC) : $(OBJS)
	$(CC) -o $(EXEC) $(OFLAGS) $(OBJS) $(LFLAGS)

.PHONY: clean
clean:
	@rm -f $(OBJS) $(EXEC)

