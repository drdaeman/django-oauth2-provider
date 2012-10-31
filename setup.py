#!/usr/bin/env python

from setuptools import setup, find_packages
import provider

setup(
    name='django-oauth2-provider',
    version=provider.__version__,
    description='Provide OAuth2 access to your app',
    long_description=open('README.rst').read(),
    author='Alen Mujezinovic',
    author_email='alen@caffeinehit.com',
    url = 'https://github.com/caffeinehit/django-oauth2-provider',
    packages = find_packages(exclude=["example"]),
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Framework :: Django',
    ],
    install_requires=[
        "shortuuid>=0.1"
    ],
    include_package_data=True,
    zip_safe=False,
    use_2to3=True,
)
