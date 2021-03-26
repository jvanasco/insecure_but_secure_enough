"""insecure_but_secure_enough installation script.
"""
import os
import re

from setuptools import setup
from setuptools import find_packages

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = (
    description
) = "Lightweight tools for signing and encrypting cookies, urls and stuff. This package isn't really secure, but it is secure enough for most needs."
with open(os.path.join(HERE, "README.md")) as fp:
    long_description = fp.read()

# store version in the init.py
with open(
    os.path.join(HERE, "src", "insecure_but_secure_enough", "__init__.py")
) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)

requires = [
    "pycryptodomex",
    "simplejson",
    "six",
]
tests_require = ["pytest"]
testing_extras = tests_require + []

setup(
    name="insecure_but_secure_enough",
    version=VERSION,
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
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
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    test_suite="tests",
)
