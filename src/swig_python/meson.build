message('Building Python bindings...')

swig_py_target = custom_target('swig-python',
                     command : [join_paths(meson.source_root(), 'tools', 'swig_python.sh'),
                                sed, '@OUTDIR@/gasdk_py_wrap.c', '@OUTDIR@', '@INPUT0@', '@INPUT1@'],
                     input : ['swig_gasdk.i', 'python_extra.py_in'],
                     output : ['gasdk_py_wrap.c'],
                     depend_files :
                         files(join_paths('..', '..', 'include', 'gdk.h'),
                               join_paths('..', '..', 'include', 'greenlight.h'),
                           ))

python_inc_dir = python_installation.get_variable('INCLUDEPY')

libswig_python = static_library('swig_python', swig_py_target,
                                include_directories : python_inc_dir,
                                c_args : [],
                                dependencies : dependencies + [python_dep])

meson.add_install_script(join_paths(meson.source_root(), 'tools', 'install_python.sh'), meson.project_version(), python_installation.path())
