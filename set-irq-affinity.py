#!/usr/bin/python

# Supported drivers: ixgbe

import getopt
import os
import re
import sys

first_core = None
interface = None
verbose = 0
dry_run = False

def die(s):
	print(s)
	exit(1)

def usage():
	print("set_irq_affinity.py {-i INTERFACE} [--dry-run] [-c core] [-hv]")

try:
	opts, args = getopt.getopt(sys.argv[1:], "hvi:c:",["dry-run"])
except getopt.GetoptError as err:
	die(err)

for o, a in opts:
	if o in ("-i"):
		interface = a
	elif o in ("-h"):
		usage()
		sys.exit(0)
	elif o in ("-v"):
		verbose += 1
	elif o in ("--dry-run"):
		dry_run = True
	elif o in ("-c"):
		first_core = int(a)

if interface == None:
	usage()
	die("Interface not specidied")

driver_path = os.readlink("/sys/class/net/%s/device/driver" % interface)
driver = os.path.basename(os.path.normpath(driver_path))

with open("/proc/interrupts", 'r') as f:
	lines = f.readlines()

if driver == "ixgbe":
	pattern = "^%s-TxRx-[0-9]*$" % interface
elif driver == "i40e":
	pattern = "^i40e-%s-TxRx-[0-9]*$" % interface
else:
	die("Driver '%s' not supported" % driver)

irqs = []

p = re.compile(pattern)
for i in range (1, len(lines)):
	columns = lines[i].split()
	for col in columns:
		m = re.match(p, col.strip())
		if m != None:
			irq = columns[0].strip(" :")
			if not irq.isdigit():
				print("/proc/interrupts:%d: Invalid irq" % i + 1)
				sys.exit(1)
			irqs.append(int(irq))

if verbose > 1:
	print("irqs=", irqs)
for i in range(0, len(irqs)):
	with open("/proc/irq/%d/smp_affinity" % irqs[i], 'w+') as f:
		if first_core == None:
			affinity = None
		else:
			affinity = 1 << (first_core + i)

		if verbose > 0:
			lines = f.readlines()
			assert(len(lines) > 0)
			old_affinity = lines[0].strip()

			log = "irq %d, affinity 0x%s" % (irqs[i], old_affinity)
			if affinity != None:
				log += "->0x%08x" % affinity
			print(log)

		if affinity != None:
			if not dry_run:
				f.write("%x" % affinity)

sys.exit(0)
