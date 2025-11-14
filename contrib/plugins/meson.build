contrib_plugins = ['bbv', 'cache', 'cflow', 'drcov', 'execlog', 'hotblocks',
                   'hotpages', 'howvec', 'hwprofile', 'ips', 'stoptrigger', 'lktrace']
if host_os != 'windows'
  # lockstep uses socket.h
  contrib_plugins += 'lockstep'
endif

t = []
if get_option('plugins')
  foreach i : contrib_plugins
    if host_os == 'windows'
      if i == 'lktrace'
        t += shared_module(i, files('lktrace/lktrace.c', 'lktrace/syscall.c') + 'win32_linker.c',
                          include_directories: ['../../include/qemu', 'lktrace'],
                          link_depends: [win32_qemu_plugin_api_lib],
                          link_args: win32_qemu_plugin_api_link_flags,
                          dependencies: glib)
      else
        t += shared_module(i, files(i + '.c') + 'win32_linker.c',
                          include_directories: '../../include/qemu',
                          link_depends: [win32_qemu_plugin_api_lib],
                          link_args: win32_qemu_plugin_api_link_flags,
                          dependencies: glib)
      endif
    else
      if i == 'lktrace'
        t += shared_module(i, files('lktrace/lktrace.c', 'lktrace/syscall.c'),
                          include_directories: ['../../include/qemu', 'lktrace'],
                          dependencies: glib)
      else
        t += shared_module(i, files(i + '.c'),
                          include_directories: '../../include/qemu',
                          dependencies: glib)
      endif
    endif
  endforeach
endif
if t.length() > 0
  alias_target('contrib-plugins', t)
else
  run_target('contrib-plugins', command: [python, '-c', ''])
endif

plugin_modules += t
