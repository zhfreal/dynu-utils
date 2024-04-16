#!/usr/bin/env python3
#cython: language_level=3

from setuptools import setup, find_packages

setup(
    name='dynu-utils',
    version="1.2.0",
    author='zhfreal',
    author_email='zhfreal@gmail.com',
    description='util for dynu ddns domains and records',
    keywords='dynu, ddns, records, domains',
    long_description="list domains, list records, add domains, add records, update records, delete records",
    long_description_content_type='text/markdown',
    url='https://github.com/zhfreal/dynu-utils',
    project_urls={
        'Documentation': 'https://github.com/zhfreal/dynu-utils',
        'Bug Reports':
            'https://github.com/zhfreal/dynu-utils/issues',
        'Source Code': 'https://github.com/zhfreal/dynu-utils',
        # 'Funding': '',
        # 'Say Thanks!': '',
    },
    install_requirts=[
        'requests>=2.31.0',
        'gevent>=24.2.1'
    ],
    # package_dir={'': 'src'},
    packages=['src'],
    classifiers=[
        # see https://pypi.org/classifiers/
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3 :: Only',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': [
            'dynu-utils=src.dynu:main']
    },
    python_requires='>=3.8',
    # install_requires=['Pillow'],
    extras_require={
        'dev': ['check-manifest'],
        # 'test': ['coverage'],
    },
)

