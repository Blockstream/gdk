swig_target = custom_target('swig',
                     command : [join_paths(meson.source_root(), 'tools', 'swig.sh'),
                                sed, '@BUILD_DIR@/../gasdk_wrap.c', '@BUILD_DIR@/..', '@INPUT0@', '@INPUT1@',
                                join_paths(meson.build_root(), 'libwally-core', 'src', 'swig_java', 'wallycore.jar'),
                                java_target],
                     input : ['swig_gasdk.i', 'jni_extra.java_in'],
                     output : ['gasdk_wrap.c'])

java_inc_dir = include_directories(join_paths(java_home, 'include'),
                                   join_paths(java_home, 'include', build_machine.system()))

libswig_java = static_library('swig_java', swig_target,
                              include_directories : java_inc_dir,
                              c_args : ['-fno-strict-aliasing'],
                              dependencies : dependencies)

meson.add_install_script(join_paths(meson.source_root(), 'tools', 'install.sh'))
