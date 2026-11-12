project('con-gen', 'c',
  version : '0.1',
  meson_version : '>=0.60.0',
  default_options : [
    'c_std=gnu99',
    'buildtype=debugoptimized',
    'b_ndebug=if-release',
    'warning_level=1',
    'werror=true',
  ],
)

cc = meson.get_compiler('c')
fs = import('fs')
is_linux = host_machine.system() == 'linux'

srcs = files(
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
  'con-gen.c',
)

c_args = [
  '-pipe',
  '-finline-functions',
  '-fPIC',
  '-Wstrict-prototypes',
  # FIXME: rework timers to get rid of function align, it's dangerous
  '-falign-functions=16',
]

# Release-style builds keep asserts disabled (as the SCons build did by default).
if get_option('buildtype') != 'debug'
  c_args += '-DNDEBUG'
endif

deps = [dependency('threads')]

if is_linux
  deps += cc.find_library('dl')
else
  deps += cc.find_library('execinfo')
  deps += cc.find_library('util')
endif

have_transport = false

# netmap
netmap_opt = get_option('netmap')
if not netmap_opt.disabled()
  # A local netmap (its headers in include/) wins over the system one
  netmap_args = []
  netmap_dir = get_option('netmap_dir')
  if netmap_dir != ''
    netmap_include = meson.project_source_root() / netmap_dir / 'include'
    if not fs.is_file(netmap_include / 'net/netmap_user.h')
      error('netmap_dir: ' + netmap_include + '/net/netmap_user.h not found')
    endif
    netmap_args = ['-I' + netmap_include]
  elif fs.is_file('netmap/include/net/netmap_user.h')
    netmap_args = ['-I' + meson.project_source_root() / 'netmap/include']
  endif
  if cc.has_header('net/netmap_user.h', args : netmap_args)
    c_args += netmap_args
    c_args += '-DHAVE_NETMAP'
    srcs += files('netmap.c')
    have_transport = true
  elif netmap_opt.enabled()
    error('netmap requested but net/netmap_user.h not found')
  endif
endif

# XDP (Linux only)
xdp_opt = get_option('xdp')
if is_linux and not xdp_opt.disabled()
  have_xdp = false
  bpf_dep = cc.find_library('bpf', required : false)
  if cc.has_header('linux/if_xdp.h') and bpf_dep.found()
    if cc.has_header('bpf/xsk.h')
      deps += bpf_dep
      have_xdp = true
    else
      xdp_dep = cc.find_library('xdp', required : false)
      if cc.has_header('xdp/xsk.h') and xdp_dep.found()
        c_args += '-DHAVE_XDP_XDP_XSK'
        deps += [xdp_dep, bpf_dep]
        have_xdp = true
      endif
    endif
  endif
  if have_xdp
    c_args += '-DHAVE_XDP'
    srcs += files('xdp.c')
    have_transport = true
  elif xdp_opt.enabled()
    error('XDP requested but libbpf/libxdp not found')
  endif
endif

# libpcap
pcap_opt = get_option('pcap')
if not pcap_opt.disabled()
  pcap_dep = dependency('libpcap', required : false)
  if not pcap_dep.found()
    pcap_dep = cc.find_library('pcap', required : false)
  endif
  if pcap_dep.found() and cc.has_header('pcap/pcap.h', dependencies : pcap_dep)
    c_args += '-DHAVE_PCAP'
    srcs += files('pcap.c')
    deps += pcap_dep
    have_transport = true
  elif pcap_opt.enabled()
    error('pcap requested but libpcap not found')
  endif
endif

# DPDK
dpdk_dep = dependency('libdpdk', required : get_option('dpdk'))
if dpdk_dep.found()
  c_args += '-DHAVE_DPDK'
  srcs += files('dpdk.c')
  deps += dpdk_dep
  have_transport = true
endif

if not have_transport
  error('At least one transport (netmap, xdp, pcap, dpdk) must exist')
endif

executable('con-gen', srcs,
  c_args : c_args,
  link_args : ['-rdynamic'],
  dependencies : deps,
  install : true,
)
