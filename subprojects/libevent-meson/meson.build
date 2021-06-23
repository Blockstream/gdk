project('libevent', ['c'], meson_version : '>= 0.58.0')

compiler = meson.get_compiler('c')

message('Building libevent...')

run_cmd_args = []

target_os = meson.get_cross_property('target_os', '')
if target_os != ''
    run_cmd_args += ['--' + target_os]
endif

res = run_command(join_paths(meson.source_root(), 'tools', 'buildlibevent.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

libevent_dir_name = 'libevent'

incdir = join_paths('..', '..', meson.build_root().split('/')[-1], libevent_dir_name, 'include')
libdir = join_paths(meson.build_root(), libevent_dir_name, 'build', 'lib')

all_libs = []

libevent_lib = compiler.find_library('event_core', dirs : libdir)
all_libs += libevent_lib
cross_win_build = meson.get_cross_property('target_os', '') == 'windows'
if not cross_win_build
    libevent_pthreads_lib = compiler.find_library('event_pthreads', dirs : libdir)
    all_libs += libevent_pthreads_lib
endif
libevent_extra_lib = compiler.find_library('event_extra', dirs : libdir)
all_libs += libevent_extra_lib

libevent_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : all_libs)
