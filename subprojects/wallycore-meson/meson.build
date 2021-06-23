project('libwally-core', ['c'], meson_version : '>= 0.58.0')

compiler = meson.get_compiler('c')

message('Building libwally-core...')

run_cmd_args = []

target_os = meson.get_cross_property('target_os', '')
if target_os != ''
    run_cmd_args += ['--' + target_os]
else
    run_cmd_args += ['--linux']
endif

if get_option('b_sanitize') == 'address'
    run_cmd_args += ['--asan']
endif

res = run_command(join_paths(meson.source_root(), 'tools', 'buildlibwally-core.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

wallycore_dir_name = 'libwally-core'

incdir = join_paths('..', '..', meson.build_root().split('/')[-1], wallycore_dir_name, 'build', 'include')
libdir = join_paths(meson.build_root(), wallycore_dir_name, 'build', 'lib')

secp256k1_lib = compiler.find_library('secp256k1', dirs : libdir)
wallycore_lib = compiler.find_library('wallycore', dirs : libdir)

wallycore_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : [wallycore_lib, secp256k1_lib])
