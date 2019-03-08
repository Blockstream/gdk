project('gdk', ['c', 'cpp'], version: '0.0.7', meson_version : '>= 0.47')

# commonly used checks
compiler = meson.get_compiler('cpp')

cross_win_build = meson.is_cross_build() and meson.get_cross_property('target_os') == 'windows'
cross_iphone_build = meson.is_cross_build() and meson.get_cross_property('target_os').contains('iphone')
cross_android_build = host_machine.system() == 'android'
is_freebsd = host_machine.system().startswith('freebsd')
is_clang = compiler.get_id() == 'clang'
freebsd_requires_gold = is_freebsd and is_clang
use_gold = (build_machine.system() == 'linux' or cross_android_build or freebsd_requires_gold) and not cross_win_build

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
if get_option('lto')
    add_project_arguments(['-flto'], language : 'cpp')
    add_project_link_arguments(['-flto'], language : 'cpp')
endif
if use_gold
    add_project_link_arguments(['-fuse-ld=gold', '-ldl'], language : 'cpp')
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
    '-Wl,-z,defs',
    '-Wl,-z,now',
    '-Wl,-z,relro',
    '-Wl,-z,noexecstack'
]

if use_gold
    add_project_link_arguments(common_link_args, language : ['c', 'cpp'])
endif

if get_option('b_sanitize') == 'address' and is_clang
    add_project_arguments(['-shared-libasan'], language : ['c', 'cpp'])
    add_project_link_arguments(['-shared-libasan'], language : ['c', 'cpp'])
endif

if get_option('buildtype') == 'debug'
    add_project_arguments(['-g', '-fno-omit-frame-pointer', '-D_GLIBCXX_ASSERTIONS', '-D_GLIBCXX_DEBUG', '-D_GLIBCXX_DEBUG_PEDANTIC'], language : ['c', 'cpp'])
else
    add_project_arguments(['-DNDEBUG'], language : ['c', 'cpp'])
endif

if meson.is_cross_build()
    archs = meson.get_cross_property('archs')
    if archs != []
        add_project_arguments(meson.get_cross_property('archs'), language : ['c', 'cpp'])
    endif
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
        java_target = '1.7'
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

clang_tidy_name = 'run-clang-tidy' + get_option('clang-tidy-version')
clang_tidy = find_program(clang_tidy_name, clang_tidy_name + '.py', required : false)

pvs_studio_analyzer = find_program('pvs-studio-analyzer', required : false)

sphinx_build = find_program('sphinx-build', required : false)
if sphinx_build.found()
    source_docs = join_paths(meson.source_root(), 'docs', 'source')
    custom_target('apidocs', output : 'apidocs', command : [sphinx_build, '-b', 'html', '-a',
                  '-c', source_docs, source_docs, join_paths(meson.source_root(), 'docs', 'build', 'html')])
else
    message('apidocs generation is not available')
endif

# dependencies
threads_dep = dependency('threads')
m_dep = compiler.find_library('m', required : false)
atomic_dep = compiler.find_library('atomic', required : false)
dl_dep = compiler.find_library('dl', required : false)
ws2_dep = compiler.find_library('ws2_32', required : cross_win_build)
bcrypt_dep = compiler.find_library('bcrypt', required : cross_win_build)
ssp_dep = compiler.find_library('ssp', required : cross_win_build)
log_dep = compiler.find_library('log', required : cross_android_build)

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

# includes
sdk_inc_dir = '.'

incdir = include_directories([sdk_inc_dir])

# builds
subdirs = ['src']
foreach n : subdirs
    subdir(n)
endforeach
