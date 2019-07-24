sources = ['amount.cpp',
           'amount.hpp',
           'assertion.cpp',
           'assertion.hpp',
           'auth_handler.hpp',
           'autobahn_wrapper.hpp',
           'boost_wrapper.hpp',
           'containers.hpp',
           'containers.cpp',
           'exception.cpp',
           'exception.hpp',
           'ffi_c.cpp',
           'ga_auth_handlers.hpp',
           'ga_auth_handlers.cpp',
           'ga_wally.cpp',
           'ga_wally.hpp',
           'ga_session.cpp',
           'ga_session.hpp',
           'ga_strings.cpp',
           'ga_strings.hpp',
           'ga_tor.cpp',
           'ga_tor.hpp',
           'ga_tx.cpp',
           'ga_tx.hpp',
           'gsl_wrapper.hpp',
           'http_client.cpp',
           'http_client.hpp',
           'logging.hpp',
           'memory.hpp',
           'network_parameters.cpp',
           'session.cpp',
           'session.hpp',
           'signer.cpp',
           'signer.hpp',
           'socks_client.cpp',
           'socks_client.hpp',
           'transaction_utils.cpp',
           'transaction_utils.hpp',
           'tx_list_cache.cpp',
           'tx_list_cache.hpp',
           'utils.hpp',
           'utils.cpp',
           'xpub_hdkey.cpp',
           'xpub_hdkey.hpp',
           'wally_wrapper.h']

headers = ['../include/gdk.h']

sources += headers

if clang_format.found()
    custom_target('clang-format', input : sources, output : 'clang-format', command : [clang_format, '-i', '@INPUT@'])
endif

if clang_tidy.found() or pvs_studio_analyzer.found()
    fix_compile_commands = custom_target('fix-compile-commands', output : 'compile_commands.json', capture : true,
                                          command : ['sed', '-e', 's/-MD//g', '-e', 's/-pipe//g', '-e', 's!src!./src!g', 'compile_commands.json'])
endif

if clang_tidy.found()
    custom_target('clang-tidy', output : 'clang-tidy', command : [clang_tidy, '-header-filter=../src/*',
                  '-checks=*,-fuchsia*,-google-*,-llvm-*,-mpi-*,-objc-*,-zircon-*', '-p=' + join_paths(meson.build_root(), 'src')],
                   depends : fix_compile_commands)
endif

if pvs_studio_analyzer.found()
    custom_target('pvs-studio-analyzer', output : 'pvs-studio-analyzer', command : [join_paths(meson.source_root(), 'tools', 'run_pvs_studio_analyzer.sh'), meson.build_root()], depends : fix_compile_commands)
endif

dependencies = subproject_deps + library_deps

local_link_args = []
link_whole = []
if build_jni
    message('Building JNI bindings...')
    subdir('swig_java')
    link_whole += [libswig_java]
else
    message('Disabled JNI bindings')
endif

if build_swig_python
    subdir('swig_python')
    link_whole += [libswig_python]
else
    message('Disabled Python bindings')
endif

wallycore_libdir = wallycore.get_variable('libdir')
if host_machine.system() == 'linux' or cross_android_build
    local_link_args += ['-Wl,--whole-archive', join_paths(wallycore_libdir, 'libwallycore.a'), '-Wl,--no-whole-archive']
    if build_jni and build_machine.system() == 'darwin'
        local_link_args += ['-Wl,--whole-archive', join_paths(wallycore_libdir, '..', '..', 'src', '.libs', 'libswig_java.a'), '-Wl,--no-whole-archive']
    endif
elif build_machine.system() == 'darwin'
    local_link_args += ['-Wl,-force_load', join_paths(wallycore_libdir, 'libwallycore.a')]
endif

install_headers(
    headers,
    subdir : 'gdk'
)

if cross_android_build
    libga_installdir = join_paths('lib', meson.get_cross_property('ndk_lib_dir'))
else
    libga_installdir = 'lib'
endif

libga = both_libraries('greenaddress',
                        sources,
                        include_directories : incdir,
                        link_whole : link_whole,
                        link_args : local_link_args,
                        dependencies : dependencies,
                        install : true,
                        install_dir : libga_installdir)

if cross_iphone_build
    output = 'allsym_libgreenaddress.a'
    archiver = custom_target('archiver',
                             output : output,
                             command : [join_paths(meson.source_root(), 'tools', 'archiver.sh'), meson.build_root()],
                             build_always_stale : true,
                             build_by_default : true,
                             depends : libga)
endif

# TODO: macOS doesn't have an "official" version of objcopy, maybe brew has something for us.. android works though, because NDK has its own objcopy in the toolchain
if build_machine.system() != 'darwin' or cross_android_build
	# Extract the debug symbols from the un-stripped version in build-**
	custom_target('external debug symbols',
		      output : 'libgreenaddress.syms',
		      command : [find_program('objcopy'), '--only-keep-debug', libga.full_path(), join_paths(meson.build_root(), 'src', 'libgreenaddress.syms')],
		      build_by_default : true,
		      build_always_stale : true,
		      install : true,
		      install_dir : libga_installdir,
		      depends : libga)
endif

# tests
subdirs = ['swift']
foreach n : subdirs
    subdir(n)
endforeach
