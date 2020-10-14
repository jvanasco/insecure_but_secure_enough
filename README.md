![Python package](https://github.com/jvanasco/insecure_but_secure_enough/workflows/Python%20package/badge.svg)

This package is insecure, but secure enough.

The idea for secure_enough to allow for "autologin cookies" and "instant login" urls for social web applications.

This package is similar to "ItsDangerous", which is now popular but was unknown when this package was first written.

Two important things to note:

1. You should not use this module for financial transactions or sensitive info.  That would be egregiously silly.
2. If you log someone in with this , you should note the login as "insecure" and require them to provide a password to view sensitive data or any 'write' activity.


This package supports the following schemes for encrypting data:

1. RSA encryption (really!)
2. AES encryption

This package supports the following schemes for signing data:

1. No signing ( just serialize )
2. HMAC SHA1 signing
3. HMAC SHA256 signing
4. Request signing, as compatible with Facebook's auth scheme.

The data transformation is as follows :

1. serialize ( convert to JSON )
2. base64 encode
3. ? obfuscate
4. ? encrypt
5. ? sign

UNTESTED

* You can create "configuration objects" that accept a timestamp and return an appropriate secret/encryption key


===================

There is a bit of documentation in:
	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/insecure_but_secure_enough/__init__.py

The following files give an interactive demo:

	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo.py
	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo_performance.py

Also note that the github source distribution contains tests.

===================


# ToDo:

The timebased providers is entirely untested.
* build out the demo and the test suite to support it.
