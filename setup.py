#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='pandaloginvestigator',
    version='0.1',
    description='Pandalogs analysis tool',
    url='https://ClonedOne@bitbucket.org/ClonedOne/seminar.git',
    install_requires=['numpy', 'cement', 'scipy', 'matplotlib'],
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
