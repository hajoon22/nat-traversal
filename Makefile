example-icmp-unreach: example-unreach-client.o example-unreach-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
	gcc -o unreach-client example-unreach-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
	gcc -o unreach-server example-unreach-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
example-unreach-client.o: example/icmp-unreach/client.c
	gcc -c example/icmp-unreach/client.c -o example-unreach-client.o
example-unreach-server.o: example/icmp-unreach/server.c
	gcc -c example/icmp-unreach/server.c -o example-unreach-server.o

example-icmp-exceeded: example-exceeded-client.o example-exceeded-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
	gcc -o exceeded-client example-exceeded-client.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
	gcc -o exceeded-server example-exceeded-server.o traversal.o stun.o unreach.o icmp-nt.o checksum.o exceeded.o
example-exceeded-client.o: example/icmp-exceeded/client.c
	gcc -c example/icmp-exceeded/client.c -o example-exceeded-client.o
example-exceeded-server.o: example/icmp-exceeded/server.c
	gcc -c example/icmp-exceeded/server.c -o example-exceeded-server.o

traversal.o: traversal/traversal.c traversal/traversal.h
	gcc -c traversal/traversal.c -o traversal.o
stun.o: traversal/stun/stun.c traversal/stun/stun.h
	gcc -c traversal/stun/stun.c -o stun.o
unreach.o: traversal/icmp/unreach.c traversal/icmp/unreach.h
	gcc -c traversal/icmp/unreach.c -o unreach.o
exceeded.o: traversal/icmp/exceeded.c traversal/icmp/exceeded.h
	gcc -c traversal/icmp/exceeded.c -o exceeded.o
icmp-nt.o: traversal/icmp/nt.c traversal/icmp/nt.h
	gcc -c traversal/icmp/nt.c -o icmp-nt.o
checksum.o: traversal/checksum/checksum.c traversal/checksum/checksum.h
	gcc -c traversal/checksum/checksum.c -o checksum.o

clean:
	rm -rf *.o
