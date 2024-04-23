target=dns
ifname=ens33
loader=dns-loader

.phony: kern user clean debug load unload status

kern:
	clang -O2 -c -g -S \
	-D __BPF_TRACING__ \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-Wno-visibility \
	-target bpf -emit-llvm ./dns_kern.c -o $(target).ll

	llc -march=bpf -filetype=obj -o $(target).o $(target).ll

# user:$(common).o ./dns_user.c
user: ./dns_user.c
	gcc -Wall $< -o $(loader)  -lbpf -lxdp

load:
	# sudo xdp-loader unload eth0 --all
	sudo xdp-loader load -m skb $(ifname) $(target).o -s xdp_dns
	sudo xdp-loader status $(ifname)

unload:
	sudo xdp-loader unload $(ifname) --all

status: 
	sudo xdp-loader status $(ifname)
