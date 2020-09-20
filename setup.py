#!/usr/bin/env python3

try:
    from setuptools.core import setup
except ImportError:
    from distutils.core import setup

try:
    import pypandoc
    have_pypandoc = True
except ImportError:
    have_pypandoc = False

with open('version.py') as f:
    exec(f.read())

if have_pypandoc:
    # convert markdown to reStructured Text
    rst = pypandoc.convert('README.md', 'rst', format='markdown')
else:
    print('You don\'t have pypandoc. Copying README.md as README.rst '
          'though it will not look good.')
    rst = open('README.md').read()

# write the converted README file
with open('README.rst', 'w') as outfile:
    outfile.write(rst)

# read requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f]

setup(
    name = 'ih2torrent',
    py_modules = ['ih2torrent', 'version'],
    install_requires = requirements,
    version = __version__,
    description = 'Convert a torrent infohash or magnet URI to a .torrent file using DHT and metadata protocol. Asyncio based.',
    author = 'Mostafa Razavi',
    license = "GPL",
    author_email = 'mostafa@sepent.com',
    url = 'https://github.com/elektito/ih2torrent',
    download_url = 'https://github.com/elektito/ih2torrent/tarball/' + __version__,
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
