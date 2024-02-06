#!/bin/bash

#--interface --peer --workers --client --server --core

TRANSPORT="netmap"
INETRFACE=""
AFFINITY=0
PEER=""
N_WORKERS=1
LFlag=0

ARGS=""

PROG=$(basename $(realpath $0))

die()
{
	echo $1 > /dev/tty
	pkill -9 -x $PROG
}

usage()
{
	echo "$PROG {-i interface} {-p peer-interface} [-n workers] [-a affinity] [-L]"
}

read_hwaddr()
{
	if test -d "/sys/class/net/$1/"; then
		cat "/sys/class/net/$1/address"
	else
		die "Interface '$1' doesn't exists"
	fi
}

while getopts "t:i:p:n:a:L" opt; do
	case ${opt} in
	t)
		TRANSPORT=$OPTARG
		;;
	i)
		INTERFACE=$OPTARG
		;;
	p)
		PEER=$OPTARG
		;;
	n)
		N_WORKERS=$OPTARG
		;;
	a)
		AFFINITY=$OPTARG
		;;
	L)
		Lflag=1
		;;
	esac
done

if [ ! $INTERFACE ]; then
	usage
	die "Interface not specified"

fi

if [ ! $PEER ]; then
	usage
	die "Peer interface not specified"
fi

INTERFACE_HWADDR=$(read_hwaddr $INTERFACE)
PEER_HWADDR=$(read_hwaddr $PEER)

ethtool -L $INTERFACE combined $N_WORKERS
./set-irq-affinity.py -i $INTERFACE -c $AFFINITY

CONCURRENCY=$((1000 * $N_WORKERS))
#CONCURRENCY=1

ARGS="$ARGS --$TRANSPORT -i $INTERFACE -S $INTERFACE_HWADDR -D $PEER_HWADDR -c $CONCURRENCY"

if [ $Lflag ]; then
	ARGS="$ARGS -s 10.10.10.1 -L"
else
	ARGS="$ARGS -s 10.10.20.1-10.20.20.3 -d 10.10.10.1"
fi

LAST_WORKER=$((N_WORKERS - 1))

for i in $(seq 0 $LAST_WORKER)
do
	if [ $i -ne 0 ]; then
		ARGS="$ARGS --"
	fi

	a=$(($AFFINITY + $i))

	ARGS="$ARGS -q $i -a $a"
done

echo "./con-gen $ARGS"
./con-gen $ARGS
