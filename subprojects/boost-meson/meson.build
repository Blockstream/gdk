project('boost', ['c'], meson_version : '>= 0.41.1')

compiler = meson.get_compiler('cpp')

run_cmd_args = []
if meson.is_cross_build()
    run_cmd_args += ['--' + meson.get_cross_property('target_os')]
endif

if get_option('buildtype') == 'debug'
    run_cmd_args += ['-g', '-fno-omit-frame-pointer', '-D_GLIBCXX_ASSERTIONS', '-D_GLIBCXX_DEBUG', '-D_GLIBCXX_DEBUG_PEDANTIC']
endif

message('Building Boost...')
res = run_command(join_paths(meson.source_root(), 'tools', 'buildboost.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

boost_dir_name = 'boost'

incdir = join_paths('..', '..', meson.build_root().split('/')[-1], boost_dir_name, 'build', 'include')
libdir = join_paths(meson.build_root(), boost_dir_name, 'build', 'lib')

chrono_lib = compiler.find_library('boost_chrono', dirs : libdir)
log_lib = compiler.find_library('boost_log', dirs : libdir)
system_lib = compiler.find_library('boost_system', dirs : libdir)
thread_lib = compiler.find_library('boost_thread', dirs : libdir)

boost_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : [chrono_lib, log_lib, system_lib, thread_lib])
