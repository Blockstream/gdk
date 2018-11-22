project('openssl', ['c'], meson_version : '>= 0.41.1')

compiler = meson.get_compiler('c')

message('Building OpenSSL...')
run_cmd_args = []
if meson.is_cross_build()
    run_cmd_args += ['--' + meson.get_cross_property('target_os')]
endif
res = run_command(join_paths(meson.source_root(), 'tools', 'buildopenssl.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

openssl_dir_name = 'openssl'

incdir = join_paths('..', '..', meson.build_root().split('/')[-1], openssl_dir_name, 'build', 'include')
libdir = join_paths(meson.build_root(), openssl_dir_name, 'build', 'lib')

crypto_lib = compiler.find_library('crypto', dirs : libdir)
ssl_lib = compiler.find_library('ssl', dirs : libdir)

openssl_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : [ssl_lib, crypto_lib])
