try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'words words',
    'author': 'Adam Maxwell',
    'url': 'https://github.com/catalyst256/gobbler',
    'download_url': 'https://github.com/catalyst256/gobbler',
    'author_email': '',
    'version': '0.1',
    'install_requires': [''], #required modules
    'packages': ['gobbler', 'gobbler/layers', 'gobbler/parsers', 'gobbler/uploaders'], 
    'scripts': ['bin/gobbler'],
    'name': 'gobbler'
}

setup(**config)