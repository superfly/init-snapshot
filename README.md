# Fly Init

This is a public snapshot of Fly's init code. It powers every Firecracker microvm we run for our users.

It is Rust-based and we thought making it public (even in this very limited fashion) could help as a reference for people making Rust-based init programs.

# Usage

Please note that our init is tailored for firecracker microvms. These instructions might not quite work and differ from what we do in production.

- Build with `cargo build --release`
- Create a device for the init
```bash
fallocate -l 64M tmpinit
mkfs.ext2 tmpinit
mkdir initmount
mount -o loop,noatime tmpinit initmount
mkdir initmount/fly
cp target/x86_64-unknown-linux-musl/release/init initmount/fly/init
cp run.json initmount/fly/run.json # more on this later
umount initmount
```
- Attach this device as /dev/vda
- Attach your rootfs as /dev/vdb
- Attach a vsock virtio device

## initrd

This init should also work packaged as an initrd. However, we're not running it as such at the time of this writing.

```bash
mkdir -p tmpcpio/fly
cp target/x86_64-unknown-linux-musl/release/init tmpcpio/fly/init
cp run.json tmpcpio/fly/run.json
cd tmpcpio
ls | cpio --null --create -V --format=newc -O ../initrd.cpio
```

You can then use initrd.cpio as your initrd parameter.