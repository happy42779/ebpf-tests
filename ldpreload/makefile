target=libc.so.6

.phony: export unset lookup

all:
	gcc -shared -fPIC -o $(target) ./dns_intercept.c -ldl

lookup:
	gcc lookup.c -o lookup

export: 
	export LD_PRELOAD=./$(target) 

unset:
	unset LD_PRELOAD

