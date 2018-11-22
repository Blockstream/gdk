project('libwally-core', ['cpp'], meson_version : '>= 0.41.1')

compiler = meson.get_compiler('cpp')

message('Building libwally-core...')
run_cmd_args = []
if meson.is_cross_build()
    run_cmd_args += ['--' + meson.get_cross_property('target_os')]
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
