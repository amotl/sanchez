#!/usr/bin/env python

# http://peak.telecommunity.com/DevCenter/setuptools
# http://peak.telecommunity.com/DevCenter/PythonEggs

import sys
sys.path.insert(0, 'src/')

from sanchez import __VERSION__
version = ".".join(str(n) for n in __VERSION__)

from setuptools import setup, find_packages

setup (
    name='sanchez',
    version=version,
    author = "Andreas Motl",
    author_email = "amotl@vz.net",
    packages = find_packages('src'),
    include_package_data = True,
    package_dir = {'':'src'},
    namespace_packages = ['sanchez'],
    extras_require = dict(
        test = [
            'zope.testing',
            ]),
    install_requires = [
        'setuptools',
        'pynids>=0.6.1',
        'dpkt==1.7',
    ],
    zip_safe = False,
    entry_points = {
        'console_scripts': [
            'sanchez = sanchez.app:main',
        ],
    },
)
