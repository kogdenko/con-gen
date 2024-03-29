# con-gen: Statefull TCP packet generator

## Introdution
- Based on BSD4.4 TCP/IP stack.
- Support: netmap, XDP, libpcap for packet sending
- Can operate with speed ~4mpps (~500kcps) on low end processor.

## Guide
### Install [netmap](https://github.com/luigirizzo/netmap)
```bash
git clone https://github.com/luigirizzo/netmap.git
cd netmap
./configure --kernel-dir=/usr/src/linux-4.9.135 --drivers=ixgbe,veth --no-apps
make
make install 
insmod netmap.ko
rmmod ixgbe
insmod  ./ixgbe-5.3.8/src/ixgbe.ko
ifconfig eth2 up
```
## Compile con-gen
```bash
./configure
make
```

## Run (example)
```bash
./con-gen -S 00:1b:21:95:69:64 -D 00:1B:21:A6:E5:3C -s 1.1.1.3 -d 1.1.1.2  -a 1 -p 80 -c 1000 -i eth2
```

## Multithread mode
```
./con-gen -S 00:1b:21:95:69:64 -D 00:1B:21:A6:E5:3C -s 1.1.1.3 -d 1.1.1.2  -a 1 -p 80 -c 1000 -i eth2-0 -- -s 1.1.1.4  -a 1 -i eth2-1
```

To delete rule after use:
```
ethtool -N eth2 delete 2045
```
