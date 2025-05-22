# con-gen: Statefull TCP packet generator

## Introdution
- Based on BSD4.4 TCP/IP stack.
- Support: netmap, XDP, libpcap for packet sending
- Can operate with speed ~4mpps (~500kcps) on low end processor.

## Guide
###Requirements
con-gen requires at least one packet-processing library: Netmap, XDP, DPDK or PCAP
### Install netmap [netmap](https://github.com/luigirizzo/netmap)
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
### Compile con-gen
```bash
scons
```

### Run
Example of Running con-gen with XDP Transport
```bash
ip l add dev vethc type veth peer veths
ip l s dev vethc up
ip l s dev veths up
./con-gen -i veths -L -s 1.1.1.1 -d 2.2.2.2 -a 4
./con-gen -i vethc -s 2.2.2.2 -d 1.1.1.1 -c 1000 -a 2
```
Example of Running con-gen with DPDK transport
```bash
./con-gen --no-pci -l 4 --proc-type=primary --file-prefix=server --vdev=net_memif0,role=server,socket=/run/net_memif0.sock,socket-abstract=no -- --dpdk -i net_memif0 -s 1.1.1.1 -d 2.2.2.2 -a 4 -L
./con-gen --no-pci -l 2 --proc-type=primary --file-prefix=client --vdev=net_memif0,role=client,socket=/run/net_memif0.sock,socket-abstract=no -- --dpdk -i net_memif0 -s 2.2.2.2 -d 1.1.1.1 -a 2 -c 1000
```

### Multithread/Multiqueue mode
```
./con-gen -S 00:1b:21:95:69:64 -D 00:1B:21:A6:E5:3C -s 1.1.1.3 -d 1.1.1.2  -a 1 -p 80 -c 1000 -i eth2-0 -- -s 1.1.1.4  -a 1 -i eth2-1
```
