all: simple_filter

simple_filter: simple_filter.c simple_filter.bpf.skel.h
	gcc -o $@ $< -lbpf

simple_filter.bpf.skel.h: simple_filter.bpf.o
	bpftool gen skeleton simple_filter.bpf.o name simple_filter > simple_filter.bpf.skel.h

simple_filter.bpf.o: simple_filter.bpf.c
	clang -target bpf -O2 -g -c $^ -o $@

clean:
	rm  -rf *.o *.skel.h simple_filter

.PHONY: clean

