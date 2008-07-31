SRCS=hash.cpp stree/stree.cpp loken.cpp converter.cpp rule.cpp output.cpp main.cpp
OBJS=$(patsubst %.cpp, %.o, $(SRCS))
EXEC=scalp
CC=g++-4.2
CFLAGS=-Wall -pedantic -O3 -fstrict-aliasing -finline-functions -funroll-loops -std=c++98 -fPIC -march=i586 -mtune=i586 -D_REENTRANT
OFLAGS=-lxml2 -lpcrecpp -lboost_thread 
LFLAGS=-L/usr/local/lib/
INC=-I/usr/include/libxml2 -I/usr/local/include

%.o : %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(EXEC) : $(OBJS)
	$(CC) -o $(EXEC) $(OFLAGS) $(OBJS) $(LFLAGS)

.PHONY: clean
clean:
	@rm -f $(OBJS) $(EXEC)

