CFLAGS= -O3 -mssse3 -mpclmul -std=gnu99 -Wall -Wextra
CXXFLAGS= -O3 -mssse3 -mpclmul -Wall -Wextra

all:
	g++ $(CXXFLAGS) -std=c++14 -c -o quartz.o quartz.cpp
	gcc $(CFLAGS) -shared -o quartz.so quartz.o