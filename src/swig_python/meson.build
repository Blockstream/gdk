message('Building Python bindings...')

swig_py_target = custom_target('swig-python',
                     command : [join_paths(meson.source_root(), 'tools', 'swig_python.sh'),
                                sed, '@OUTDIR@/gasdk_py_wrap.c', '@OUTDIR@', '@INPUT0@', '@INPUT1@'],
                     input : ['swig_gasdk.i', 'python_extra.py_in'],
                     output : ['gasdk_py_wrap.c'])

python_inc_dir = include_directories(join_paths('/usr', 'include', 'python' + python_version))

libswig_python = static_library('swig_python', swig_py_target,
                                include_directories : python_inc_dir,
                                dependencies : dependencies + [python_dep])
