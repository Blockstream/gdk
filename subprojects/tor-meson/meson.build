project('tor', ['c'], meson_version : '>= 0.58.0')

compiler = meson.get_compiler('c')

message('Building tor...')

run_cmd_args = []

target_os = meson.get_cross_property('target_os', '')
if target_os != ''
    run_cmd_args += ['--' + target_os]
endif

tor_deps = []
tor_deps += dependency('external_zlib', fallback : ['zlib', 'zlib_dep'])
tor_deps += dependency('external_libevent', fallback : ['libevent', 'libevent_dep'])
tor_deps += dependency('external_openssl', fallback : ['openssl', 'openssl_dep'])

res = run_command(join_paths(meson.source_root(), 'tools', 'buildtor.sh'), run_cmd_args)
if res.returncode() != 0
    message('--- Failed to run command (stdout) ---')
    message(res.stdout())
    message('--- Failed to run command (stderr) ---')
    message(res.stderr())
endif

tor_dir_name = 'tor'
incdir = join_paths('..', '..', meson.build_root().split('/')[-1], tor_dir_name, 'src', 'feature', 'api')
core_libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'core')
ed25519_donna_libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'ext', 'ed25519', 'donna')
ed25519_ref10_libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'ext', 'ed25519', 'ref10')
keccak_tiny_libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'ext', 'keccak-tiny')
libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'lib')
trunnel_libdir = join_paths(meson.build_root(), tor_dir_name, 'src', 'trunnel')

tor_deps += compiler.find_library('tor-app', dirs : core_libdir)
tor_deps += compiler.find_library('ed25519_donna', dirs : ed25519_donna_libdir)
tor_deps += compiler.find_library('ed25519_ref10', dirs : ed25519_ref10_libdir)
tor_deps += compiler.find_library('keccak-tiny', dirs : keccak_tiny_libdir)
tor_deps += compiler.find_library('curve25519_donna', dirs : libdir)
tor_deps += compiler.find_library('tor-buf', dirs : libdir)
tor_deps += compiler.find_library('tor-compress', dirs : libdir)
tor_deps += compiler.find_library('tor-confmgt', dirs : libdir)
tor_deps += compiler.find_library('tor-container', dirs : libdir)
tor_deps += compiler.find_library('tor-crypt-ops', dirs : libdir)
tor_deps += compiler.find_library('tor-ctime', dirs : libdir)
tor_deps += compiler.find_library('tor-dispatch', dirs : libdir)
tor_deps += compiler.find_library('tor-encoding', dirs : libdir)
tor_deps += compiler.find_library('tor-err', dirs : libdir)
tor_deps += compiler.find_library('tor-evloop', dirs : libdir)
tor_deps += compiler.find_library('tor-fdio', dirs : libdir)
tor_deps += compiler.find_library('tor-fs', dirs : libdir)
tor_deps += compiler.find_library('tor-geoip', dirs : libdir)
tor_deps += compiler.find_library('tor-intmath', dirs : libdir)
tor_deps += compiler.find_library('tor-lock', dirs : libdir)
tor_deps += compiler.find_library('tor-log', dirs : libdir)
tor_deps += compiler.find_library('tor-malloc', dirs : libdir)
tor_deps += compiler.find_library('tor-math', dirs : libdir)
tor_deps += compiler.find_library('tor-memarea', dirs : libdir)
tor_deps += compiler.find_library('tor-meminfo', dirs : libdir)
tor_deps += compiler.find_library('tor-net', dirs : libdir)
tor_deps += compiler.find_library('tor-osinfo', dirs : libdir)
tor_deps += compiler.find_library('tor-process', dirs : libdir)
tor_deps += compiler.find_library('tor-pubsub', dirs : libdir)
tor_deps += compiler.find_library('tor-sandbox', dirs : libdir)
tor_deps += compiler.find_library('tor-smartlist-core', dirs : libdir)
tor_deps += compiler.find_library('tor-string', dirs : libdir)
tor_deps += compiler.find_library('tor-term', dirs : libdir)
tor_deps += compiler.find_library('tor-thread', dirs : libdir)
tor_deps += compiler.find_library('tor-time', dirs : libdir)
tor_deps += compiler.find_library('tor-tls', dirs : libdir)
tor_deps += compiler.find_library('tor-trace', dirs : libdir)
tor_deps += compiler.find_library('tor-version', dirs : libdir)
tor_deps += compiler.find_library('tor-wallclock', dirs : libdir)
tor_deps += compiler.find_library('or-trunnel', dirs : trunnel_libdir)

tor_dep = declare_dependency(
    include_directories : include_directories(incdir),
    dependencies : tor_deps)
