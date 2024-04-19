
target=dns.o
ifname=eth0

.phony: kern user clean debug load unload status

all:
	# rm $(target)
	clang -O2 -c -D __BPF_TRACING__ -g -Wall -target bpf ./dns_kern.c -o $(target)

load:
	# sudo xdp-loader unload eth0 --all
	sudo xdp-loader load -m skb $(ifname) $(target) -s xdp_dns
	sudo xdp-loader status $(ifname)

unload:
	sudo xdp-loader unload $(ifname) --all

status: 
	sudo xdp-loader status $(ifname)
