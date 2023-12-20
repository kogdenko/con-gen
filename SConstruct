import platform
import subprocess


COMPILER = 'clang'


def die(s):
	print(s)
	Exit(1)


def bytes_to_str(b):
	return b.decode('utf-8').strip()


def system(cmd, failure_tollerance=False):
	proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	try:
		out, err = proc.communicate()
	except:
		proc.kill();
		die("Command '%s' failed, exception: '%s'" % (cmd, sys.exc_info()[0]))

	out = bytes_to_str(out)
	err = bytes_to_str(err)
	rc = proc.returncode

#	 print("$ %s # $? = %d\n%s\n%s" % (cmd, rc, out, err))

	if rc != 0 and not failure_tollerance:
		die("Command '%s' failed, return code: %d" % (cmd, rc))

	return rc, out, err


def check_xdp(conf):
	if not conf.CheckHeader('linux/if_xdp.h'):
		return False
	if not conf.CheckHeader('xdp/xsk.h'):
		return False
	if not conf.CheckLib('bpf'):
		return False
	return True


def check_dpdk(env, conf):
	rc, cflags, _ = system("pkg-config --cflags libdpdk", True)
	if rc != 0:
		return False

	rc, s, _ = system("pkg-config --libs-only-l libdpdk", True)
	if rc != 0:
		return False

	libs = []
	for ldflag in s.split():
		libs.append(ldflag[2:])

	rc, ldflags, _ = system("pkg-config --libs-only-L --libs-only-other libdpdk", True)
	if rc != 0:
		return False

	env.Append(CFLAGS = cflags)
	env.Append(LIBS = libs)
	env.Append(LINKFLAGS = ldflags)

	return True


AddOption('--debug-build', action = 'store_true',
	help = 'Debug build', default = False)

AddOption("--without-netmap", action = 'store_true',
	help = "Don't use netmap", default = False)

AddOption("--without-pcap", action = 'store_true',
	help = "Don't use libpcap", default = False)

if platform.system() == "Linux":
	AddOption("--without-xdp", action = 'store_true',
		help = "Don't use XDP", default = False)

AddOption("--without-dpdk", action = 'store_true',
	help = "Don't use dpdk", default = False)


g_srcs = [
	'bsd44/uipc_socket.c',
	'bsd44/in_pcb.c',
	'bsd44/ip_input.c',
	'bsd44/ip_output.c',
	'bsd44/ip_icmp.c',
	'bsd44/udp_usrreq.c',
	'bsd44/tcp_debug.c',
	'bsd44/tcp_subr.c',
	'bsd44/tcp_usrreq.c',
	'bsd44/tcp_input.c',
	'bsd44/tcp_output.c',
	'bsd44/tcp_timer.c',
	'bsd44/if_ether.c',
	'bsd44/glue.c',
	'gbtcp/list.c',
	'gbtcp/htable.c',
	'gbtcp/timer.c',
	'gbtcp/inet.c',
	'gbtcp/tcp.c',
	'subr.c',
	'netstat.c',
	'con-gen.c'
]

g_cflags = [
	'-g',
	'-Wall',
	'-Werror',
	'-pipe',
	'-finline-functions',
	'-pthread',
	'-fPIC',
	'-std=gnu99',
	'-Wstrict-prototypes',
]

g_ldflags = [
	'-rdynamic',
	'-L.'
]

g_libs = [
	'pthread'
]

if platform.system() == 'Linux':
	g_libs.append('dl')
else:
	g_libs.append('execinfo')
	g_libs.append('util')

if GetOption('debug_build'):
	g_cflags.append('-O0')
else:
	g_cflags.append('-O2')
	g_cflags.append('-DNDEBUG')

# NOTE: gcc only. Need for timers
# FIXME: rework timers to get rid of function aligin, it's dangerous
g_cflags.append('-falign-functions=16')

env=Environment(CC = COMPILER)

conf = Configure(env)
have_transport = False
if not GetOption('without_netmap'):
	if conf.CheckHeader('net/netmap_user.h'):
		g_cflags.append('-DHAVE_NETMAP')
		have_transport = True
		g_srcs.append('netmap.c')
if platform.system() == "Linux" and not GetOption('without_xdp'):
	if (check_xdp(conf)):
		g_cflags.append('-DHAVE_XDP')
		have_transport = True
		g_libs.append('bpf')
		g_libs.append('xdp')
		g_srcs.append('xdp.c')
if not GetOption('without_pcap'):
	if conf.CheckHeader('pcap/pcap.h'):
		g_cflags.append('-DHAVE_PCAP')
		have_transport = True
		g_libs.append('pcap')
		g_srcs.append('pcap.c')
if not GetOption('without_dpdk'):
	if (check_dpdk(env, conf)):
		g_cflags.append('-DHAVE_DPDK')
		have_transport = True
		g_srcs.append('dpdk.c')
		print("Checking for DPDK... yes")
	else:
		print("Checking for DPDK... no")

if not have_transport:
	print("At least one transport must exists")
	Exit(1)
env.Append(CFLAGS = ' '.join(g_cflags))
env.Append(LINKFLAGS = ' '.join(g_ldflags))
env.Append(LIBS = g_libs)

con_gen = env.Program('con-gen', g_srcs)
env.Install('/usr/local/bin', con_gen)
env.Alias('install', '/usr/local/bin')
