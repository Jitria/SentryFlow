# make vmlinux.h in this directory
.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# delete all object file and vmlinux.h
.PHONY: clean
clean:
	rm -rf *.o vmlinux.h