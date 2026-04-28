mfirouz@cmtcdeu78041066:~/filesys_fuzzer$ cat ../linux/boot.sh 
../virtme/virtme-run   --kimg arch/x86/boot/bzImage   --rwdir ../testfuzz   --memory 2G   --cpus 2   --qemu-opts   -enable-kvm   -drive file=$(pwd)/ntfs_disk.img,format=raw,if=virtio

mfirouz@cmtcdeu78041066:~/filesys_fuzzer$ cat ../linux/mount.sh 
mkdir -p /tmp/ntfs
mount -t ntfs3 -o force /dev/vda /tmp/ntfs

touch /tmp/a
findmnt -T  /tmp/a
touch /tmp/ntfs/a
findmnt -T  /tmp/ntfs/a/
TARGET    SOURCE   FSTYPE OPTIONS
/tmp/ntfs /dev/vda ntfs3  rw,relatime,uid=0,gid=0,force,iocharset=utf8,prealloc
root@(none):/home/mfirouz/linux#
mfirouz@cmtcdeu78041066:~/filesys_fuzzer$ 