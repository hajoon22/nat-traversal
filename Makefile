example-icmp-unreach: example-unreach-client-udp.o example-unreach-server-udp.o example-unreach-client-icmp.o example-unreach-server-icmp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o unreach-udp-client example-unreach-client-udp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o unreach-udp-server example-unreach-server-udp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o unreach-icmp-client example-unreach-client-icmp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o unreach-icmp-server example-unreach-server-icmp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
example-unreach-client-udp.o: example/icmp-unreach/udp/client.c
	gcc -c example/icmp-unreach/udp/client.c -o example-unreach-client-udp.o
example-unreach-server-udp.o: example/icmp-unreach/udp/server.c
	gcc -c example/icmp-unreach/udp/server.c -o example-unreach-server-udp.o
example-unreach-client-icmp.o: example/icmp-unreach/icmp/client.c
	gcc -c example/icmp-unreach/icmp/client.c -o example-unreach-client-icmp.o
example-unreach-server-icmp.o: example/icmp-unreach/icmp/server.c
	gcc -c example/icmp-unreach/icmp/server.c -o example-unreach-server-icmp.o

example-icmp-exceeded: example-exceeded-client-icmp.o example-exceeded-server-icmp.o example-exceeded-client-udp.o example-exceeded-server-udp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o exceeded-udp-client example-exceeded-client-udp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o exceeded-udp-server example-exceeded-server-udp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o exceeded-icmp-client example-exceeded-client-icmp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o exceeded-icmp-server example-exceeded-server-icmp.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
example-exceeded-client-udp.o: example/icmp-exceeded/udp/client.c
	gcc -c example/icmp-exceeded/udp/client.c -o example-exceeded-client-udp.o
example-exceeded-server-udp.o: example/icmp-exceeded/udp/server.c
	gcc -c example/icmp-exceeded/udp/server.c -o example-exceeded-server-udp.o
example-exceeded-client-icmp.o: example/icmp-exceeded/icmp/client.c
	gcc -c example/icmp-exceeded/icmp/client.c -o example-exceeded-client-icmp.o
example-exceeded-server-icmp.o: example/icmp-exceeded/icmp/server.c
	gcc -c example/icmp-exceeded/icmp/server.c -o example-exceeded-server-icmp.o

example-spoof-udp: example-spoof-udp-server.o example-spoof-udp-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o spoof-udp-client example-spoof-udp-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o spoof-udp-server example-spoof-udp-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
example-spoof-udp-server.o: example/spoof-udp/server.c
	gcc -c example/spoof-udp/server.c -o example-spoof-udp-server.o
example-spoof-udp-client.o: example/spoof-udp/client.c
	gcc -c example/spoof-udp/client.c -o example-spoof-udp-client.o

example-spoof-echo: example-spoof-echo-server.o example-spoof-echo-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o spoof-echo-client example-spoof-echo-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
	gcc -o spoof-echo-server example-spoof-echo-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o ipip.o spoofudp.o spoof-nt.o spoofecho.o
example-spoof-echo-server.o:
	gcc -c example/spoof-echo/server.c -o example-spoof-echo-server.o
example-spoof-echo-client.o:
	gcc -c example/spoof-echo/client.c -o example-spoof-echo-client.o

traversal.o: traversal/traversal.c traversal/traversal.h
	gcc -c traversal/traversal.c -o traversal.o
stun.o: traversal/stun/stun.c traversal/stun/stun.h
	gcc -c traversal/stun/stun.c -o stun.o
unreach.o: traversal/icmp/unreach/unreach.c traversal/icmp/unreach/unreach.h
	gcc -c traversal/icmp/unreach/unreach.c -o unreach.o
exceeded.o: traversal/icmp/exceeded/exceeded.c traversal/icmp/exceeded/exceeded.h
	gcc -c traversal/icmp/exceeded/exceeded.c -o exceeded.o
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

checksum.o: traversal/checksum/checksum.c traversal/checksum/checksum.h
	gcc -c traversal/checksum/checksum.c -o checksum.o

clean:
	rm -rf *.o
	rm -rf spoof-udp-client spoof-udp-server
	rm -rf exceeded-client exceeded-server
	rm -rf unreach-icmp-server unreach-icmp-client
	rm -rf unreach-udp-server unreach-udp-client
