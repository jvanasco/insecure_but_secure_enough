"""insecure_but_secure_enough installation script.
"""
import os

from setuptools import setup
from setuptools import find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, "README.md")).read()
README = README.split("\n\n", 1)[0] + "\n"

requires = [
	  'PyCrypto >= 2.6',
	  'simplejson',
    ]

setup(name="insecure_but_secure_enough",
      version="0.0.2",
      description="Lightweight tools for signing and encrypting cookies, urls and stuff. This package isn't really secure, but its secure enough for most needs.",
      long_description=README,
      classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
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
