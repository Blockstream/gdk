project('gdk_rust', 'c', meson_version : '>= 0.51.2')

message('Building gdk_rust...')

cargo_script = find_program(join_paths(meson.source_root(), 'tools', 'buildgdk_rust.sh'))
objcopy = find_program('objcopy', required : false)

run_cmd_args = [cargo_script]

if get_option('buildtype') == 'debug'
  run_cmd_args += ['debug']
else
  run_cmd_args += ['release']
endif

run_cmd_args += ['@OUTPUT@']
run_cmd_args += [meson.source_root()]
run_cmd_args += [meson.build_root()]

if objcopy.found()
    run_cmd_args += [objcopy]
else
    run_cmd_args += ['']
endif

target_os = meson.get_cross_property('target_os', '')
if target_os != ''
    run_cmd_args += ['--' + target_os]
endif

rust_sources = [
  'Cargo.toml',
  'src/error.rs',
  'src/lib.rs',
  'src/serialize.rs',

  'gdk_common/Cargo.toml',
  'gdk_common/src/be/mod.rs',
  'gdk_common/src/be/address.rs',
  'gdk_common/src/be/blockheader.rs',
  'gdk_common/src/be/outpoint.rs',
  'gdk_common/src/be/transaction.rs',
  'gdk_common/src/wally/mod.rs',
  'gdk_common/src/wally/ffi.rs',
  'gdk_common/src/constants.rs',
  'gdk_common/src/error.rs',
  'gdk_common/src/lib.rs',
  'gdk_common/src/mnemonic.rs',
  'gdk_common/src/model.rs',
  'gdk_common/src/network.rs',
  'gdk_common/src/password.rs',
  'gdk_common/src/session.rs',
  'gdk_common/src/util.rs',

  'gdk_electrum/Cargo.toml',
  'gdk_electrum/src/db.rs',
  'gdk_electrum/src/error.rs',
  'gdk_electrum/src/interface.rs',
  'gdk_electrum/src/lib.rs',
  'gdk_electrum/src/model.rs',
  'gdk_electrum/src/tools.rs',

  'gdk_rpc/src/coins/btc.rs',
  'gdk_rpc/src/coins/liq.rs',
  'gdk_rpc/src/coins.rs',
  'gdk_rpc/src/errors.rs',
  'gdk_rpc/src/lib.rs',
  'gdk_rpc/src/network.rs',
  'gdk_rpc/src/session.rs',
  'gdk_rpc/src/settings.rs',
  'gdk_rpc/src/wallet.rs'

]

gdk_rust_target = custom_target('libgdk_rust',
                               input : rust_sources,
                               output : 'libgdk_rust.a',
                               command : run_cmd_args)

incdir = include_directories(join_paths('..', '..', meson.build_root().split('/')[-1], 'subprojects', 'gdk_rust'))

gdk_rust_deps = [subproject('libwally-core').get_variable('wallycore_dep')]
gdk_rust_dep = declare_dependency(
  include_directories : incdir,
  dependencies : gdk_rust_deps
)
