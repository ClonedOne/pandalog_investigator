#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='pandaloginvestigator',
    version='0.2',
    author='Giorgio Severi',
    description='Panda logs analysis tool',
    url='https://github.com/ClonedOne/pandalog_investigator',
    install_requires=['numpy', 'cement', 'networkx', 'jsonpickle'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={'console_scripts': [
        'pandaloginvestigator=pandaloginvestigator.pandaloginvestigator:main']
    },
    classifiers=[
        'Development Status :: Beta',
        'Framework :: Cement',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Malware analysis']
)
