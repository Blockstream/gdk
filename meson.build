project('gdk', ['c', 'cpp'], version: '0.0.21', meson_version : '>= 0.51.2')

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
    add_project_link_arguments(['-fuse-ld=gold', '-ldl'], language : 'cpp')
elif cross_android_build
    if is_darwin and not lto
        add_project_link_arguments(['-fuse-ld=bfd', '-ldl'], language : 'cpp')
    else
        add_project_link_arguments(['-fuse-ld=lld', '-ldl'], language : 'cpp')
    endif
endif
if cross_iphone_build
    add_project_arguments(['-miphoneos-version-min=11.0'], language : 'cpp')
    add_project_link_arguments(['-miphoneos-version-min=11.0'], language : 'cpp')
endif

common_compile_options = [
    '-Wextra',
    '-D_FORTIFY_SOURCE=2',
    '-fasynchronous-unwind-tables',
    '-fexceptions',
    '-fstack-protector-strong',
    '-fvisibility=hidden',
    '-DGDK_BUILD',
]

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

if get_option('b_sanitize') == 'address' and is_clang
    add_project_arguments(['-shared-libasan'], language : ['c', 'cpp'])
    add_project_link_arguments(['-shared-libasan'], language : ['c', 'cpp'])
endif

if debug
    add_project_arguments(['-ggdb3', '-fno-omit-frame-pointer', '-D_GLIBCXX_ASSERTIONS', '-D_GLIBCXX_DEBUG', '-D_GLIBCXX_DEBUG_PEDANTIC'], language : ['c', 'cpp'])
    if debug_optimized
        add_project_arguments(['-Og'], language : ['c', 'cpp'])
    endif
else
    add_project_arguments(['-DNDEBUG'], language : ['c', 'cpp'])
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
    add_project_link_arguments(['-lPromiseKit'], language : 'swift')
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
swig = find_program('swig', required : false)
if swig.found()
    pymodule = import('python3')
    python3 = pymodule.find_python()

    environment_variables = [
        'JAVA_HOME',
        'JAVA_TARGET'
    ]
    foreach v : environment_variables
        res = run_command(python3, '-c', 'import os; print(os.environ["' + v + '"], end = "")')
        if res.returncode() == 0
            stdout = res.stdout()
            set_variable(v.to_lower(), stdout)
            message(v + ' set to ' + stdout)
        else
            set_variable(v.to_lower(), '')
        endif
    endforeach

    python_config_dir = host_machine.system()
    if python_config_dir.contains('linux')
        python_config_dir = 'x86_64-linux-gnu'
    endif

    python_version = get_option('python-version')
    run_command('virtualenv', '--clear', '-p', 'python' + python_version, join_paths(meson.build_root(), 'venv'))
    python_dep = compiler.find_library('python' + python_version + 'm', dirs : join_paths(meson.build_root(), 'venv', 'lib', 'python' + python_version, 'config-' + python_version + 'm-' + python_config_dir), required : false)

    if java_target == ''
        java_target = '1.8'
    endif

    javac = add_languages('java', required : false)
    if not javac or java_home == ''
        message('Java not found or $JAVA_HOME not set. JNI bindings are disabled.')
    else
        java = find_program('java')
    endif
endif

jni_deps  = swig.found() and javac and java_home != ''
jni_disabled = cross_win_build or cross_iphone_build or not jni_deps
build_jni = (jni_deps or cross_android_build) and not jni_disabled
build_swig_python = swig.found() and python_dep.found() and not cross_iphone_build and not cross_android_build

clang_format = find_program('clang-format', required : false)

clang_tidy_name = 'clang-tidy' + get_option('clang-tidy-version')
clang_tidy = find_program(clang_tidy_name, required : false)

pvs_studio_analyzer = find_program('pvs-studio-analyzer', required : false)
infer = find_program('infer', required : false)

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
    backtrace_dep = compiler.find_library('backtrace', required : false)
    if backtrace_dep.found()
        library_deps += backtrace_dep
        add_project_arguments(['-DHAVE_BACKTRACE'], language : ['c', 'cpp'])
    endif
endif
library_deps += compiler.find_library('execinfo', required : is_freebsd)

subproject_deps = []

wallycore = subproject('libwally-core')
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
sdk_inc_dir = '.'

incdir = include_directories([sdk_inc_dir])

# builds
subdirs = ['src']
foreach n : subdirs
    subdir(n)
endforeach
