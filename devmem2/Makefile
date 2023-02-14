all:
	gcc -o shmem2 shmem2.c -lrt

shared:
	gcc -fPIC -shared -o shmem2.so shmem2_shared.c -lrt

clean:
	rm -f shmem2
	rm -f shmem2.so

