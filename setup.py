try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Gobbler was written to allow you to take a pcap file and import into a number of different services.',
    'author': 'Adam Maxwell',
    'url': 'https://github.com/catalyst256/gobbler',
    'download_url': 'https://github.com/catalyst256/gobbler',
    'author_email': 'catalyst256@gmail.com',
    'version': '0.1.1',
    'install_requires': [''], #required modules
    'packages': ['gobbler', 'gobbler/layers', 'gobbler/parsers', 'gobbler/uploaders'], 
    'scripts': ['bin/gobbler'],
    'name': 'gobbler'
}

setup(**config)