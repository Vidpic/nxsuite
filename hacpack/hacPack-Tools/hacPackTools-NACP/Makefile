CXX = g++
CXXFLAGS = -std=gnu++11 -Wall -O2 -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64 -D_GLIBCXX_USE_CXX11_ABI=0 -finput-charset=utf-8 -fexec-charset=utf-8
LDFLAGS = -ltinyxml2 -static -static-libgcc -static-libstdc++
INCLUDE = -I ./tinyxml2/
LIBDIR = ./tinyxml2/

all:
	cd tinyxml2 && $(MAKE)
	$(MAKE) hptnacp

.cpp.o:
	$(CXX) $(INCLUDE) -c $(CXXFLAGS) -o $@ $<

hptnacp: main.o nacp.o
	$(CXX) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

main.o: main.cpp
nacp.o: nacp.cpp nacp.hpp

clean:
	rm -f *.o hptnacp hptnacp.exe

clean_full:
	rm -f *.o hptnacp hptnacp.exe
	cd tinyxml2 && $(MAKE) clean
