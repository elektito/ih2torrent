#!/usr/bin/env python3

from distutils.core import setup
from pip.req import parse_requirements
from pip.download import PipSession

import pypandoc

# convert markdown to reStructured Text
rst = pypandoc.convert('README.md', 'rst', format='markdown')

# writes converted file
with open('README.rst','w') as outfile:
    outfile.write(rst)

# read requirements from requirements.txt
requirements = parse_requirements('requirements.txt', session=PipSession())
requirements = [str(r.req) for r in requirements]

setup(
    name = 'ih2torrent',
    py_modules = ["ih2torrent"],
    install_requires = requirements,
    version = '0.1.2',
    description = 'Convert a torrent infohash or magnet URI to a .torrent file using DHT and metadata protocol. Asyncio based.',
    author = 'Mostafa Razavi',
    author_email = 'mostafa@sepent.com',
    url = 'https://github.com/elektito/ih2torrent',
    download_url = 'https://github.com/elektito/ih2torrent/tarball/0.1.1',
    keywords = ['bittorrent', 'torrent', 'infohash', 'magnet', 'dht', 'metadata', 'metainfo', 'asyncio'],
    classifiers = [
        "Programming Language :: Python :: 3"
    ],
    entry_points = {
        "console_scripts": [
            "ih2torrent=ih2torrent:main",
        ],
    },
)
