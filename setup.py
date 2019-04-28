"""insecure_but_secure_enough installation script.
"""
import os
import re

from setuptools import setup
from setuptools import find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, "README.md")).read()
README = README.split("\n\n", 1)[0] + "\n"

# store version in the init.py
with open(
        os.path.join(
            os.path.dirname(__file__),
            'insecure_but_secure_enough', '__init__.py')) as v_file:
    VERSION = re.compile(
        r".*__VERSION__ = '(.*?)'",
        re.S).match(v_file.read()).group(1)

requires = [
    'PyCrypto >= 2.6',
    'simplejson',
]

setup(
    name="insecure_but_secure_enough",
    version=VERSION,
    description="Lightweight tools for signing and encrypting cookies, urls and stuff. This package isn't really secure, but it is secure enough for most needs.",
    long_description=README,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
    keywords="web pylons pyramid",
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    url="https://github.com/jvanasco/insecure_but_secure_enough",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    tests_require = requires,
    install_requires = requires,
    test_suite= 'tests',
)
