qemu-system-x86_64 \
    -m 128M \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1 pti=on kaslr quiet" \
    -cpu qemu64,+smep \
    -monitor /dev/null \
    -nographic \
    -smp 2 \
    -smp cores=2 \
    -smp threads=1 \
    -no-reboot