project('zlib', ['c'], meson_version : '>= 0.58.0')

compiler = meson.get_compiler('c')

message('Building zlib...')

run_cmd_args = []

target_os = meson.get_cross_property('target_os', '')
if target_os != ''
    run_cmd_args += ['--' + target_os]
endif

res = run_command(join_paths(meson.source_root(), 'tools', 'buildzlib.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

zlib_dir_name = 'zlib'

incdir = join_paths('..', '..', meson.build_root().split('/')[-1], zlib_dir_name)
libdir = join_paths(meson.build_root(), zlib_dir_name)

zlib_lib = compiler.find_library('z', dirs : libdir)

zlib_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : [zlib_lib])
