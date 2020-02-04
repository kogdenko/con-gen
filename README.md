# con-gen: Statefull TCP packet generator

## Introdution
- Based on BSD4.4 TCP/IP stack.
- Use netmap.
- Can operate with speed ~4mpps (~500kcps) on low end processor.

## Compile 
```bash
./configure
make
```

## Example
```bash
./con-gen -L -S 00:30:4f:4e:e9:2b -D 60:e3:27:03:03:97 -s 2.2.2.2 -d 2.2.2.4 -i rl0
```

## Benchmark
fx8350
```bash
./con-gen -L -a 1 -D 72:9c:29:36:5e:02 -S 72:9c:29:36:5e:01 -d 172.16.7.2 -s 172.16.7.1 -i veth_g  --tcp-timewait-timeout=0
```
~ 510kcps (4mpps)

## Known bugs
- Ephemeral port exhaustion. (without --tcp-timewait-timeout=0)
