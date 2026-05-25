all: tcp-block

tcp-block: main.cpp mac.cpp ip.cpp tcp.cpp ethhdr.h mac.h ip.h tcp.h
	g++ -o tcp-block main.cpp mac.cpp ip.cpp tcp.cpp -lpcap

clean:
	rm -f tcp-block