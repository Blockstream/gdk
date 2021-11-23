"""setuptools config for gdk """

import os

kwargs = {
    'name': 'greenaddress',
    'version': os.environ['GDK_VERSION'],
    'description': 'gdk Bitcoin library',
    'long_description': 'Python bindings for the gdk Bitcoin library',
    'url': 'https://github.com/blockstream/gdk',
    'author': 'Blockstream',
    'author_email': 'inquiries@blockstream.com',
    'license': 'MIT',
    'zip_safe': False,

    'classifiers': [
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.9',
    ],

    'keywords': 'Bitcoin wallet library BIP32 BIP38 BIP39 secp256k1',
    'project_urls': {
        'Documentation': 'https://github.com/blockstream/gdk',
        'Source': 'https://github.com/blockstream/gdk',
        'Tracker': 'https://github.com/blockstream/gdk/issues',
    },

    'packages': ['greenaddress'],
    'package_dir': {'': os.environ['PYTHON_DESTDIR']},
}

import platform
import distutils
import distutils.command.build_py

class _build_py(distutils.command.build_py.build_py):

    def build_libgreenaddress(self):

        # Copy the so that has just been built to the build_dir that distutils expects it to be in
        # The extension of the built lib is dylib on osx
        so_ext = 'dylib' if platform.system() == 'Darwin' else 'dll' if platform.system() == 'Windows' else 'so'
        src_so = 'lib/libgreenaddress.{}'.format(so_ext)
        distutils.dir_util.mkpath(self.build_lib)
        dest_so = os.path.join(self.build_lib, 'libgreenaddress.so')
        distutils.file_util.copy_file(src_so, dest_so)

    def run(self):
        # Override build_py to first build the c library, then perform the normal python build.
        # Overriding build_clib would be more obvious but that results in setuptools trying to do
        # build_py first, which fails because the wallycore/__init__.py is created by making the
        # clib
        self.build_libgreenaddress()
        distutils.command.build_py.build_py.run(self)

kwargs['cmdclass'] = {'build_py': _build_py}

# Force Distribution to have ext modules. This is necessary to generate the correct platform
# dependent filename when generating wheels because the building of the underlying wally c libs
# is effectively hidden from distutils - which means it assumes it is building a pure python
# module.
from distutils.dist import Distribution
Distribution.has_ext_modules = lambda self: True

from setuptools import setup
setup(**kwargs)
