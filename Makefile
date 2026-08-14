COMMON = traversal.o stun.o icmp.o icmp-nt.o checksum.o keepalive.o ipip.o spoofudp.o spoof-nt.o spoofecho.o istun.o local.o

example-icmp-unreach: example-unreach-client-udp.o example-unreach-server-udp.o example-unreach-client-icmp.o example-unreach-server-icmp.o $(COMMON)
	gcc -o unreach-udp-client example-unreach-client-udp.o $(COMMON)
	gcc -o unreach-udp-server example-unreach-server-udp.o $(COMMON)
	gcc -o unreach-icmp-client example-unreach-client-icmp.o $(COMMON)
	gcc -o unreach-icmp-server example-unreach-server-icmp.o $(COMMON)
example-unreach-client-udp.o: example/icmp-unreach/udp/client.c
	gcc -c example/icmp-unreach/udp/client.c -o example-unreach-client-udp.o
example-unreach-server-udp.o: example/icmp-unreach/udp/server.c
	gcc -c example/icmp-unreach/udp/server.c -o example-unreach-server-udp.o
example-unreach-client-icmp.o: example/icmp-unreach/icmp/client.c
	gcc -c example/icmp-unreach/icmp/client.c -o example-unreach-client-icmp.o
example-unreach-server-icmp.o: example/icmp-unreach/icmp/server.c
	gcc -c example/icmp-unreach/icmp/server.c -o example-unreach-server-icmp.o

example-icmp-exceeded: example-exceeded-client-icmp.o example-exceeded-server-icmp.o example-exceeded-client-udp.o example-exceeded-server-udp.o $(COMMON)
	gcc -o exceeded-udp-client example-exceeded-client-udp.o $(COMMON)
	gcc -o exceeded-udp-server example-exceeded-server-udp.o $(COMMON)
	gcc -o exceeded-icmp-client example-exceeded-client-icmp.o $(COMMON)
	gcc -o exceeded-icmp-server example-exceeded-server-icmp.o $(COMMON)
example-exceeded-client-udp.o: example/icmp-exceeded/udp/client.c
	gcc -c example/icmp-exceeded/udp/client.c -o example-exceeded-client-udp.o
example-exceeded-server-udp.o: example/icmp-exceeded/udp/server.c
	gcc -c example/icmp-exceeded/udp/server.c -o example-exceeded-server-udp.o
example-exceeded-client-icmp.o: example/icmp-exceeded/icmp/client.c
	gcc -c example/icmp-exceeded/icmp/client.c -o example-exceeded-client-icmp.o
example-exceeded-server-icmp.o: example/icmp-exceeded/icmp/server.c
	gcc -c example/icmp-exceeded/icmp/server.c -o example-exceeded-server-icmp.o

example-spoof-udp: example-spoof-udp-server.o example-spoof-udp-client.o $(COMMON)
	gcc -o spoof-udp-client example-spoof-udp-client.o $(COMMON)
	gcc -o spoof-udp-server example-spoof-udp-server.o $(COMMON)
example-spoof-udp-server.o: example/spoof-udp/server.c
	gcc -c example/spoof-udp/server.c -o example-spoof-udp-server.o
example-spoof-udp-client.o: example/spoof-udp/client.c
	gcc -c example/spoof-udp/client.c -o example-spoof-udp-client.o

example-spoof-echo: example-spoof-echo-server.o example-spoof-echo-client.o $(COMMON)
	gcc -o spoof-echo-client example-spoof-echo-client.o $(COMMON)
	gcc -o spoof-echo-server example-spoof-echo-server.o $(COMMON)
example-spoof-echo-server.o: example/spoof-echo/server.c
	gcc -c example/spoof-echo/server.c -o example-spoof-echo-server.o
example-spoof-echo-client.o: example/spoof-echo/client.c
	gcc -c example/spoof-echo/client.c -o example-spoof-echo-client.o

example-istun: example-istun.o $(COMMON)
	gcc -o example-istun example-istun.o $(COMMON)

example-istun.o: example/istun/istun.c
	gcc -c example/istun/istun.c -o example-istun.o

traversal.o: traversal/traversal.c traversal/traversal.h
	gcc -c traversal/traversal.c -o traversal.o
stun.o: traversal/stun/stun.c traversal/stun/stun.h
	gcc -c traversal/stun/stun.c -o stun.o
istun.o: traversal/istun/istun.c traversal/istun/istun.h
	gcc -c traversal/istun/istun.c -o istun.o
icmp.o: traversal/icmp/icmp.c traversal/icmp/icmp.h
	gcc -c traversal/icmp/icmp.c -o icmp.o
icmp-nt.o: traversal/icmp/nt.c traversal/icmp/nt.h
	gcc -c traversal/icmp/nt.c -o icmp-nt.o

ipip.o: traversal/ipip/ipip.c traversal/ipip/ipip.h
	gcc -c traversal/ipip/ipip.c -o ipip.o
spoofudp.o: traversal/spoof/udp/udp.c traversal/spoof/udp/udp.h
	gcc -c traversal/spoof/udp/udp.c -o spoofudp.o
spoofecho.o: traversal/spoof/echo/echo.c traversal/spoof/echo/echo.h
	gcc -c traversal/spoof/echo/echo.c -o spoofecho.o
spoof-nt.o: traversal/spoof/nt.c traversal/spoof/nt.h
	gcc -c traversal/spoof/nt.c -o spoof-nt.o

local.o: traversal/common/local.c traversal/common/local.h
	gcc -c traversal/common/local.c -o local.o
checksum.o: traversal/common/checksum.c traversal/common/checksum.h
	gcc -c traversal/common/checksum.c -o checksum.o
keepalive.o: traversal/common/keepalive.c traversal/common/keepalive.h
	gcc -c traversal/common/keepalive.c -o keepalive.o

clean:
	rm -rf *.o
	rm -rf example-istun
	rm -rf spoof-udp-client spoof-udp-server
	rm -rf spoof-echo-client spoof-echo-server
	rm -rf exceeded-udp-client exceeded-udp-server exceeded-icmp-client exceeded-icmp-server
	rm -rf unreach-icmp-server unreach-icmp-client
	rm -rf unreach-udp-server unreach-udp-client
