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
    'version': '0.1.4',
    'install_requires': [
        'pymongo >= 2.6.3',
        'simplejson >= 3.3.2',
        'scapy == 2.2.0-dev',
        'requests >= 2.2.1'
    ],
    'packages': ['gobbler', 'gobbler/layers', 'gobbler/parsers', 'gobbler/uploaders'], 
    'scripts': ['bin/gobbler'],
    'data_files': [('/etc', ['config/gobbler.conf'])],
    'name': 'gobbler'
}

setup(**config)