"""insecure_but_secure_enough installation script.
"""

import os
import re

from setuptools import find_packages
from setuptools import setup

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = description = (
    "Lightweight tools for signing and encrypting cookies, urls and stuff. This package isn't really secure, but it is secure enough for most needs."
)
with open(os.path.join(HERE, "README.md")) as fp:
    long_description = fp.read()

# store version in the init.py
with open(
    os.path.join(HERE, "src", "insecure_but_secure_enough", "__init__.py")
) as v_file:
    VERSION = (
        re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)  # type: ignore[union-attr]
    )

requires = [
    "pycryptodomex",
    "simplejson",
    "typing_extensions",  # Literal, Protocol
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
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    keywords="web pylons pyramid",
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    url="https://github.com/jvanasco/insecure_but_secure_enough",
    license="MIT",
    packages=find_packages(
        where="src",
    ),
    package_data={"insecure_but_secure_enough": ["py.typed"]},
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
