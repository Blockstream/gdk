project('gdk_rust', 'c', meson_version : '>= 0.58.0')

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

# Write down sources as ordered with `find ./ -name '*.rs' -o -name '*.toml' | sort | cut -c 3-`

rust_sources = [
  'Cargo.toml',
  'gdk_pin_client/Cargo.toml',
  'gdk_pin_client/src/crypto.rs',
  'gdk_pin_client/src/error.rs',
  'gdk_pin_client/src/lib.rs',
  'gdk_pin_client/src/pin.rs',
  'gdk_pin_client/src/pin_client.rs',
  'gdk_pin_client/src/pin_data.rs',
  'gdk_pin_client/src/pin_request.rs',
  'gdk_common/build.rs',
  'gdk_common/Cargo.toml',
  'gdk_common/src/be/address.rs',
  'gdk_common/src/be/blockhash.rs',
  'gdk_common/src/be/blockheader.rs',
  'gdk_common/src/be/mod.rs',
  'gdk_common/src/be/outpoint.rs',
  'gdk_common/src/be/script.rs',
  'gdk_common/src/be/sighashtype.rs',
  'gdk_common/src/be/transaction.rs',
  'gdk_common/src/be/txid.rs',
  'gdk_common/src/error.rs',
  'gdk_common/src/exchange_rates.rs',
  'gdk_common/src/lib.rs',
  'gdk_common/src/mnemonic.rs',
  'gdk_common/src/model.rs',
  'gdk_common/src/network.rs',
  'gdk_common/src/notification.rs',
  'gdk_common/src/password.rs',
  'gdk_common/src/scripts.rs',
  'gdk_common/src/session.rs',
  'gdk_common/src/state.rs',
  'gdk_common/src/util/mod.rs',
  'gdk_common/src/util/strser.rs',
  'gdk_common/src/wally/ffi.rs',
  'gdk_common/src/wally/mod.rs',
  'gdk_electrum/Cargo.toml',
  'gdk_electrum/src/account.rs',
  'gdk_electrum/src/error.rs',
  'gdk_electrum/src/headers/bitcoin.rs',
  'gdk_electrum/src/headers/liquid.rs',
  'gdk_electrum/src/headers/mod.rs',
  'gdk_electrum/src/interface.rs',
  'gdk_electrum/src/lib.rs',
  'gdk_electrum/src/pset.rs',
  'gdk_electrum/src/session.rs',
  'gdk_electrum/src/spv.rs',
  'gdk_electrum/src/store.rs',
  'gdk_registry/Cargo.toml',
  'gdk_registry/src/asset_entry.rs',
  'gdk_registry/src/assets_or_icons.rs',
  'gdk_registry/src/bin/make_hard_coded.rs',
  'gdk_registry/src/cache.rs',
  'gdk_registry/src/error.rs',
  'gdk_registry/src/file.rs',
  'gdk_registry/src/hard_coded/mod.rs',
  'gdk_registry/src/http.rs',
  'gdk_registry/src/last_modified.rs',
  'gdk_registry/src/lib.rs',
  'gdk_registry/src/params/get_assets.rs',
  'gdk_registry/src/params/mod.rs',
  'gdk_registry/src/params/refresh_assets.rs',
  'gdk_registry/src/registry_infos.rs',
  'gdk_registry/src/registry.rs',
  'gdk_rust/Cargo.toml',
  'gdk_rust/src/error.rs',
  'gdk_rust/src/exchange_rates.rs',
  'gdk_rust/src/lib.rs',
  'gdk_rust/tests/integration/integration.rs',
  'gdk_rust/tests/integration/main.rs',
  'gdk_rust/tests/integration/psbt.rs',
  'gdk_test/Cargo.toml',
  'gdk_test/src/electrum_session_ext.rs',
  'gdk_test/src/env.rs',
  'gdk_test/src/error.rs',
  'gdk_test/src/lib.rs',
  'gdk_test/src/rpc_node_ext.rs',
  'gdk_test/src/test_session.rs',
  'gdk_test/src/test_signer.rs',
  'gdk_test/src/utils.rs'
]

gdk_rust_target = custom_target('libgdk_rust',
                               input : rust_sources,
                               output : 'libgdk_rust.a',
                               command : run_cmd_args)

incdir = include_directories(join_paths('..', '..', meson.build_root().split('/')[-1], 'subprojects', 'gdk_rust'))

gdk_rust_deps = []
gdk_rust_dep = declare_dependency(
  include_directories : incdir,
  dependencies : gdk_rust_deps
)
