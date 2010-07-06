#!/usr/bin/env python
from setuptools import setup, find_packages
setup (
    name='sanchez',
    version='0.0.1',
    author = "Andreas Motl",
    author_email = "amotl@vz.net",
    packages = find_packages('src'),
    include_package_data = True,
    package_dir = {'':'src'},
    extras_require = dict(
        test = [
            'zope.testing',
            ]),
    install_requires = ['setuptools',
                        'pcap',
                        'dpkt',
                        ],
    zip_safe = False,
    )
