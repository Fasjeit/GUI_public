CC=    gcc
CXX=   g++
LD=    g++

CFLAGS= -w -O0 -mssse3 -mpclmul -std=gnu99 -Wall -Wextra -fPIC
CXXFLAGS= -w -O0 -mssse3 -mpclmul -Wall -Wextra -fPIC
#CXXFLAGS= -O2 -mssse3 -mpclmul -Wall -Wextra -fno-exceptions -fno-rtti
INCPATH= -I/usr/local/include -I/opt/local/include -I/usr/include
LDFLAGS= 
LIBPATH= -L/usr/local/lib -L/opt/local/lib -L/usr/lib
LIBS=    -lm -lcrypto
#LIBS=    -lm -lcrypto -lstdc++



#OBJ= mpkc.o dummy_core.o blas.o gfext_poly.o\
#	stat_profile.o gf2ext.o gf2ext_static.o gf2ext-sse.o blas.o\
#	quartz_core.o

OBJ = blas.o gf2ext.o gf2ext_poly.o quartz.o sha256.o library_core.o library.o fnr.o

CSRC= $(wildcard *.cpp)


ifndef QUARTZ
	QUARTZ1= QUARTZ96
else
	QUARTZ1=$(QUARTZ)
endif
	CFLAGS += -D$(QUARTZ1)
	CXXFLAGS += -D$(QUARTZ1)

ifdef HFE
        CFLAGS+=  -DHFE2
        CXXFLAGS+= -DHFE2
endif
	

#ifdef DEBUG
        CFLAGS+=  -g3 -D_DEBUG_
        CXXFLAGS+= -g3 -D_DEBUG_
	LDFLAGS += -g3
#endif

ifdef NO_SSE
	CFLAGS += -D_NO_SSE_
	CXXFLAGS += -D_NO_SSE_
endif

ifdef AVX2
	CFLAGS += -mavx2 -D_USE_AVX2_
	CXXFLAGS += -mavx2 -D_USE_AVX2_
endif

ifdef AVX
	CFLAGS += -mavx -D_USE_AVX_
	CXXFLAGS += -mavx -D_USE_AVX_
endif

ifdef GPROF
	CFLAGS += -pg
	CXXFLAGS += -pg
	LDFLAGS += -pg
endif

.PHONY: all tests tables clean

all: $(OBJ)
	$(info $$CXXFLAGS is [${CXXFLAGS}])
	$(info $$LDFLAGS is [${LDFLAGS}])
	$(info $$CXXFLAGS is [${CXXFLAGS}])
	$(CC) -shared $(LIBPATH) $(CXXFLAGS) -o libquartz.so $(OBJ) $(LIBS)

exe:
	$(CXX) -g3 -c -w -fpic exec.c
	$(CC) $(CXXFLAGS)  $(LIBPATH) -o exec exec.o $(OBJ) $(LIBS) -lstdc++

%-test: $(OBJ) %-test.o
	$(LD) $(LDFLAGS) $(LIBPATH) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCPATH) -c $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCPATH) -c $<

clean:
	rm *.o; rm *.so; rm exec

