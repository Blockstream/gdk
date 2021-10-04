project('gdk', ['c', 'cpp'], version: '0.0.45', meson_version : '>= 0.58.0')

# commonly used checks
compiler = meson.get_compiler('cpp')

cross_win_build = meson.get_cross_property('target_os', '') == 'windows'
cross_iphone_build =  meson.get_cross_property('target_os', '').contains('iphone')
cross_android_build = host_machine.system() == 'android'
is_32bit_android_build = cross_android_build and (host_machine.cpu() == 'armv7' or host_machine.cpu() == 'i686')
is_freebsd = host_machine.system().startswith('freebsd')
is_darwin = build_machine.system() == 'darwin'
is_clang = compiler.get_id() == 'clang'
freebsd_requires_gold = is_freebsd and is_clang
use_gold = (build_machine.system() == 'linux' or freebsd_requires_gold) and not cross_win_build and not cross_android_build
debug_optimized = get_option('buildtype') == 'debugoptimized'
debug = debug_optimized or get_option('buildtype') == 'debug'
lto = get_option('lto')

# header checks (must be architecture independent)
check_headers = [
    'fcntl.h',
    'stddef.h',
    'stdint.h',
    'string.h',
    'sys/epoll.h',
    'sys/stat.h',
    'unistd.h'
]

foreach h : check_headers
    compiler.has_header(h)
endforeach

# language options
add_project_arguments(compiler.first_supported_argument(['-std=c++17', '-std=c++14']), language : 'cpp')
add_project_arguments(['-Wno-deprecated-declarations', '-funsigned-char'], language : 'cpp')

static_libstdc = compiler.has_link_argument('-static-libstdc++')

# language related arguments
if lto
    add_project_arguments(['-flto'], language : 'cpp')
    add_project_link_arguments(['-flto'], language : 'cpp')
endif

if use_gold
    if is_clang and not is_freebsd and compiler.has_link_argument('-fuse-ld=lld')
        add_project_link_arguments(['-fuse-ld=lld', '-ldl'], language : 'cpp')
    else
        add_project_link_arguments(['-fuse-ld=gold', '-ldl'], language : 'cpp')
    endif
elif cross_android_build
    if is_darwin and not lto
        add_project_link_arguments(['-fuse-ld=bfd', '-ldl'], language : 'cpp')
    else
        add_project_link_arguments(['-fuse-ld=lld', '-ldl'], language : 'cpp')
    endif
endif

common_compile_options = [
    '-Wno-unknown-warning-option',
    '-Wextra',
    '-D_FORTIFY_SOURCE=2',
    '-fasynchronous-unwind-tables',
    '-fexceptions',
    '-fstack-protector-strong',
    '-fvisibility=hidden',
    '-DGDK_BUILD',
    '-D_HAVE_SQLITE_CONFIG_H'
]

if not is_freebsd and compiler.has_argument('-Wthread-safety')
    common_compile_options += ['-Wthread-safety']
endif

if get_option('time-report') and compiler.has_argument('-ftime-report')
      common_compile_options += ['-ftime-report']
endif

add_project_arguments(common_compile_options, language : ['c', 'cpp'])
add_project_arguments('-fvisibility-inlines-hidden', language : ['cpp'])

common_link_args = [
    '-Wl,-z,now',
    '-Wl,-z,relro',
    '-Wl,-z,noexecstack'
]

if (is_darwin or cross_iphone_build) and not cross_android_build
  # to generate keys in gdk_rust
  add_project_link_arguments(['-Wl,-framework,Security'], language : 'cpp')
endif

if is_darwin and not cross_android_build and not cross_iphone_build
  add_project_arguments(['-mmacosx-version-min=10.13'], language : ['c', 'cpp'])
  add_project_link_arguments(['-mmacosx-version-min=10.13'], language : ['c', 'cpp'])
endif

if cross_iphone_build
  add_project_arguments(['-miphoneos-version-min=11.0'], language : ['c', 'cpp'])
  add_project_link_arguments(['-miphoneos-version-min=11.0'], language : ['c', 'cpp'])
endif

if is_freebsd
    if freebsd_requires_gold
        common_link_args += ['-Wl,--weak-unresolved-symbols']
    else
        common_link_args += ['-Wl,-z,undefs']
    endif
endif

if (not is_darwin and not cross_win_build) or cross_android_build
    add_project_link_arguments(common_link_args, language : ['c', 'cpp'])
endif

# https://developer.android.com/ndk/guides/asan
# https://github.com/android/ndk/issues/988
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=64234
if get_option('b_sanitize') == 'address'
    if is_clang
        add_project_link_arguments(['-static-libsan'], language : ['c', 'cpp'])
    else
        add_project_link_arguments(['-shared-libasan'], language : ['c', 'cpp'])
    endif
endif

if debug
    add_project_arguments(['-ggdb3', '-fno-omit-frame-pointer', '-D_GLIBCXX_ASSERTIONS', '-D_GLIBCXX_DEBUG', '-D_GLIBCXX_DEBUG_PEDANTIC'], language : ['c', 'cpp'])
    if not is_darwin
      # Not yet supported on Apple Clang compiler
      add_project_arguments(['-D_LIBCPP_DEBUG=1'], language : ['c', 'cpp'])
    endif
    if debug_optimized
        add_project_arguments(['-Og'], language : ['c', 'cpp'])
    endif
else
    add_project_arguments(['-DNDEBUG'], language : ['c', 'cpp'])
endif
if get_option('enable-rust')
    add_project_arguments(['-DBUILD_GDK_RUST'], language : ['c', 'cpp'])
endif

if meson.is_cross_build()
    archs = meson.get_cross_property('archs')
    if archs != []
        add_project_arguments(meson.get_cross_property('archs'), language : ['c', 'cpp'])
    endif
endif

if is_32bit_android_build
    add_project_arguments('-U_FILE_OFFSET_BITS', language : ['c', 'cpp'])
endif

swift = add_languages('swift', required : false)
if swift
    add_project_arguments(['-I' + join_paths(meson.source_root(), 'src')], language : 'swift')
    add_project_arguments(['-I' + join_paths(meson.build_root(), 'libwally-core', 'include')], language : 'swift')
    add_project_arguments(['-I' + join_paths(meson.source_root(), 'src', 'swift', 'GreenAddress', '.build', 'debug')], language : 'swift')
    add_project_link_arguments(['-L' + join_paths(meson.build_root(), 'src')], language : 'swift')
    add_project_link_arguments(['-L' + join_paths(meson.source_root(), 'src', 'swift', 'GreenAddress')], language : 'swift')
    add_project_link_arguments(['-lGreenAddress'], language : 'swift')
endif

executable_c_cpp_args = ['-fPIE']
executable_link_args = []
if static_libstdc
    executable_link_args += ['-static-libstdc++']
endif

executable_link_args = []
if compiler.get_id() == 'gcc'
    executable_c_cpp_args += ['-pie']
else
    executable_link_args += ['-pie']
endif

if cross_win_build
    executable_link_args += ['-static', '-static-libgcc']
endif

sed = find_program('gsed', 'sed')
if get_option('enable-rust')
    cargo = find_program('cargo')
endif
swig = find_program('swig', required : false)
if swig.found()
    pymodule = import('python')
    python_version = get_option('python-version')
    python_installation = pymodule.find_installation('python' + python_version, required : true)
    python_exe = python_installation.path()

    environment_variables = [
        'JAVA_HOME',
        'JAVA_TARGET'
    ]
    foreach v : environment_variables
        res = run_command(python_exe, '-c', 'import os; print(os.getenv("' + v + '", ""))')
        if res.returncode() == 0
            stdout = res.stdout().strip()
            set_variable(v.to_lower(), stdout)
            message(v + ' set to "' + stdout + '"')
        else
            set_variable(v.to_lower(), '')
        endif
    endforeach

    if python_version != ''
        # FIXME: When making a python module we must avoid linking libpython
        # and allow the interpreter to provide the symbols for manylinux
        # compatibility.
        if python_installation.language_version().version_compare('<=3.9')
            # Note: Use embed:true to force linking libpython, since we don't
            # allow missing symbols in our final .so file.
            python_dep = python_installation.dependency(embed:true)
        else
            # Work around for https://github.com/mesonbuild/meson/issues/5629
            python_dep = dependency('python-@0@-embed'.format(python_version), version: '>=3', required: false)
        endif

        if not python_dep.found()
            error('Python development dependency not be found, please install python(version)-dev and try again.')
        endif
    else
        # Python only needed for reading 'environment_variables' above
        python_dep = dependency('', required : false)
    endif

    if java_target == ''
        java_target = '1.8'
    endif

    javac = add_languages('java', required : false)
    if not javac
        message('javac not found JNI bindings are disabled.')
    elif java_home == ''
        message('$JAVA_HOME not set. JNI bindings are disabled.')
    else
        java = find_program('java')
    endif
endif

jni_deps  = swig.found() and javac and java_home != ''
jni_disabled = cross_win_build or cross_iphone_build or not jni_deps
build_jni = (jni_deps or cross_android_build) and not jni_disabled
build_swig_python = swig.found() and python_dep.found() and not cross_iphone_build and not cross_android_build

ar = find_program('ar', required : not cross_android_build)
objcopy = find_program('objcopy', required : false)

clang_format = find_program('clang-format', required : false)

clang_tidy_name = 'clang-tidy' + get_option('clang-tidy-version')
clang_tidy = find_program(clang_tidy_name, required : false)

pvs_studio_analyzer = find_program('pvs-studio-analyzer', required : false)
infer = find_program('infer', required : false)
git = find_program('git', required : true)

sphinx_build = find_program('sphinx-build', required : false)
if sphinx_build.found()
    source_docs = join_paths(meson.source_root(), 'docs', 'source')
    custom_target('apidocs', output : 'apidocs', command : [sphinx_build, '-b', 'html', '-a',
                  '-c', source_docs, source_docs, join_paths(meson.source_root(), 'docs', 'build', 'html')])
else
    message('apidocs generation is not available')
endif

# dependencies
library_deps = []

library_deps += dependency('threads')
library_deps += compiler.find_library('m', required : false)
library_deps += compiler.find_library('atomic', required : false)
library_deps += compiler.find_library('dl', required : false)
library_deps += compiler.find_library('ws2_32', required : cross_win_build)
library_deps += compiler.find_library('bcrypt', required : cross_win_build)
library_deps += compiler.find_library('crypt32', required : cross_win_build)
library_deps += compiler.find_library('iphlpapi', required : cross_win_build)
library_deps += compiler.find_library('ssp', required : cross_win_build)
library_deps += compiler.find_library('log', required : cross_android_build)
if debug and build_machine.system() == 'linux'
    backtrace_dep = compiler.find_library('backtrace', has_headers : ['backtrace.h'], required : false)
    if backtrace_dep.found()
        library_deps += backtrace_dep
        add_project_arguments(['-DHAVE_BACKTRACE'], language : ['c', 'cpp'])
    endif
endif
library_deps += compiler.find_library('execinfo', required : is_freebsd)

subproject_deps = []

wallycore = subproject('libwally-core')
if get_option('enable-rust')
    gdkrust = subproject('gdk_rust')
    subproject_deps += gdkrust.get_variable('gdk_rust_dep')
endif
subproject_deps += wallycore.get_variable('wallycore_dep')
subproject_deps += dependency('external_autobahn-cpp', fallback : ['autobahn-cpp', 'autobahn_dep'])
subproject_deps += dependency('external_boost', fallback : ['boost', 'boost_dep'])
subproject_deps += dependency('external_GSL', fallback : ['GSL', 'GSL_dep'])
subproject_deps += dependency('external_json', fallback : ['json', 'nlohmann_json_dep'])
subproject_deps += dependency('external_msgpack', fallback : ['msgpack', 'msgpack_dep'])
subproject_deps += dependency('external_openssl', fallback : ['openssl', 'openssl_dep'])
subproject_deps += dependency('external_websocketpp', fallback : ['websocketpp', 'websocketpp_dep'])
subproject_deps += dependency('external_tor', fallback : ['tor', 'tor_dep'])

# includes
incdirs = ['.']
if get_option('enable-rust')
    incdirs += ['subprojects/gdk_rust']
endif
incdir = include_directories(incdirs)

# builds
subdirs = ['src']
foreach n : subdirs
    subdir(n)
endforeach

executable('make_generated_assets', 'tools/make_generated_assets.cpp',
           link_with: libga.get_static_lib(),
           dependencies: dependencies)

if get_option('enable-tests')
    test('test aes_gcm',
         executable('test_aes_gcm', 'tests/test_aes_gcm.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test json',
         executable('test_json', 'tests/test_json.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test multisession',
         executable('test_multi_session', 'tests/test_multi_session.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test networks',
         executable('test_networks', 'tests/test_networks.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))

    test('test session',
         executable('test_session', 'tests/test_session.cpp',
                    link_with: libga.get_static_lib(),
                    dependencies: dependencies
        ))
endif
