import platform

AddOption('--debug-build', action = 'store_true',
    help = 'Debug build', default = False)

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
    '-fPIC'
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
    CCFLAGS = ' '.join(cflags),
    LINKFLAGS = ' '.join(ldflags)
)
con_gen = env.Program('build/con-gen%s' % suffix, srcs)
env.Install('/usr/local/bin', con_gen)
env.Alias('install', '/usr/local/bin')
