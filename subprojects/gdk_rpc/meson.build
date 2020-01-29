project('gdk_rpc', 'c', meson_version : '>= 0.51.2')

message('Building gdk_rpc...')

cargo_script = find_program(join_paths(meson.source_root(), 'tools', 'buildgdk_rpc.sh'))
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
  'src/session.rs',
  'src/lib.rs',
  'src/settings.rs',
  'src/network.rs',
  'src/coins/liq.rs',
  'src/coins/btc.rs',
  'src/wally.rs',
  'src/wallet.rs',
  'src/util.rs',
  'src/errors.rs',
  'src/coins.rs',
  'src/constants.rs',

  'gdk_electrum/cli/src/main.rs',
  'gdk_electrum/src/client.rs',
  'gdk_electrum/src/db.rs',
  'gdk_electrum/src/error.rs',
  'gdk_electrum/src/interface.rs',
  'gdk_electrum/src/lib.rs',
  'gdk_electrum/src/model.rs',
  'gdk_electrum/src/tools.rs'
]

gdk_rpc_target = custom_target('libgdk_rpc',
                               input : rust_sources,
                               output : 'libgdk_rpc.a',
                               command : run_cmd_args)

incdir = include_directories(join_paths('..', '..', meson.build_root().split('/')[-1], 'subprojects', 'gdk_rpc'))

gdk_rpc_deps = [subproject('libwally-core').get_variable('wallycore_dep')]
gdk_rpc_dep = declare_dependency(
  include_directories : incdir,
  dependencies : gdk_rpc_deps
)
