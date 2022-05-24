import platform

AddOption('--debug-build', action = 'store_true',
    help = 'Debug build', default = False)
AddOption("--without-netmap", action = 'store_true',
    help = "Don't use netmap", default = False)
AddOption("--without-pcap", action = 'store_true',
    help = "Don't use libpcap", default = False)
if platform.system() == "Linux":
    AddOption("--without-xdp", action = 'store_true',
        help = "Don't use XDP", default = False)

srcs = [
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

cflags = [
    '-g',
    '-Wall',
    '-Werror',
    '-pipe',
    '-finline-functions',
    '-pthread',
    '-fPIC',
	'-std=gnu99',
]

ldflags = [
    '-rdynamic',
    '-L.'
]

if platform.system() == 'Linux':
    ldflags.append('-ldl')
else:
    ldflags.append('-lexecinfo')
    ldflags.append('-lutil')

if GetOption('debug_build'):
    cflags.append('-O0')
    suffix = "-d"
else:
    cflags.append('-O2')
    cflags.append('-DNDEBUG')
    suffix=""

# NOTE: gcc only. Need for timers
cflags.append('-falign-functions=16')

env=Environment(CC = 'gcc',
)

conf = Configure(env)
have_transport = False
if not GetOption('without_netmap'):
    if conf.CheckHeader('net/netmap_user.h'):
        cflags.append('-DHAVE_NETMAP')
        have_transport = True
have_xdp = False
if platform.system() == "Linux" and not GetOption('without_xdp'):
    if (conf.CheckHeader('linux/bpf.h') and conf.CheckLib('bpf')):
        cflags.append('-DHAVE_XDP')
        ldflags.append('-lbpf')
        have_xdp = True
        have_transport = True
if not have_xdp and not GetOption('without_pcap'):
    if conf.CheckHeader('pcap/pcap.h'):
        cflags.append('-DHAVE_PCAP')
        ldflags.append('-lpcap')
        have_transport = True

if not have_transport:
    print("At least one transport must exists")
    Exit(1)
env.Append(CFLAGS = ' '.join(cflags))
env.Append(LINKFLAGS = ' '.join(ldflags))

con_gen = env.Program('build/con-gen%s' % suffix, srcs)
env.Install('/usr/local/bin', con_gen)
env.Alias('install', '/usr/local/bin')
