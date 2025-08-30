![Python package](https://github.com/jvanasco/insecure_but_secure_enough/workflows/Python%20package/badge.svg)

# Quick Overview

This package is "insecure", but secure enough.

The idea behing being "secure_enough" is to allow for "autologin cookies" and "instant login" urls for social web applications.

This package is similar to "ItsDangerous" - which is now popular, but was unknown when this package was first written.

Two important things to note:

1. You should not use this module for financial transactions or sensitive info.  That would be egregiously silly.
2. If you log someone in with this, you should note the login as "insecure" and subsequently require them to provide a password (or other authentication) to view sensitive data or any 'write' activity.


This package supports the following schemes for encrypting data:

1. RSA encryption
2. AES encryption


This package supports the following schemes for signing data:

1. No signing ( just serialize )
2. HMAC SHA1 signing
3. HMAC SHA256 signing
4. Request signing, as compatible with Facebook's auth scheme.


The data transformation order is as follows :

1. serialize ( convert to JSON )
2. base64 encode
3. ? obfuscate
4. ? encrypt
5. ? sign


# Background

Long ago, I had a class that would do a trivial encryption on cookie data,
coupled with a lightweight hash to handle timeout events.  This way you wouldn't
always have to decrypt data to do a light verification.

The general flow was this:

To encode:
    cookie = encypted_data + timestamp + hash(encrypted_data + timestamp + secret)

To decode:
    (payload, timestamp, hash) = cookie
    if hash != hash (payload, timestamp, secret):
        raise InvalidHash()
    if timestamp > timeout:
        raise Timeout()
    data = decrypt(payload)

The encryption I used was a lightweight port from a CPAN (Perl) module, so it
could be blown away in seconds today.

When i decided to re-implement this, looking around I found a handful of similar
projects - which I've borrowed heavily from.

They include:

* https://github.com/dziegler/django-urlcrypt/blob/master/urlcrypt/lib.py
* http://docs.pylonsproject.org/projects/pyramid/en/1.3-branch/api/session.html#pyramid.session.signed_serialize
* https://developers.facebook.com/docs/authentication/signed_request/

This largely re-implements all of those, along with some other functionality.

Right now, data is a `base64_url_encoded` version of a string, concatenated list,
or json object (for dicts).  I opted against using `pickle`, because this format
makes it easier to work with other web technologies (js, php, etc).
This might move to an all json version one day.

Check `demo.py` to see an overview of how this works.

## Signed Requests

`signed_request_create` and `signed_request_verify`

are both handled as `@classmethods` - along with their support functions.
That means you can call them directly without an object instance.

I built them as `@classmethods` instead of package functions...
because if you want to extend the options for digest mods, you can just
subclass `SecureEnough` and overwrite `_digestmod` to add more providers.

## Encrypting and Signing Cookies

Encrypting cookies currently happens via a 'global' RSA key for an instance of
`SecureEnough()`.  [you provide details for it in the `__init__()`]

You can use timestamped based app_secrets, obfuscators & rsa keys.

The flow is as such:

1. Subclass the `ConfigurationProvider()` and overwrite the relevant hooks.
   The requesting mehtods pass a single argument - `timestamp` - which should
   give you enough to go on.
   Note that `app_secret` returns a string, while the obfuscator must return an
   object that can `obfuscate` and `deobfuscate`; and `rsa_key` requires an
   object that can `encrypt` and `decrypt`.
   This libray provides default functionality through wrapper objects you can
   mimic.

2. Instantiate a `SecureEnough()` object, and register the relevant providers

3. When encrypting data, `SecureEnough()` will ask the `ConfigurationProvider()`
   for the approprite keys/secrets for the current `time()`. When decrypting
   data, `SecureEnough()` will ask the `ConfigurationProvider()` for the
   approprite keys/secrets for the time in the cookie/hash (if there is one).

This flow will allow you to easily create a plethora of site secrets and RSA
keys -- as in a new one each day -- which means that while this module is not
actually secure, it is Secure Enough for most web applications.


UNTESTED

* You can create "configuration objects" that accept a timestamp and return an
appropriate secret/encryption key


===================

The following files give an interactive demo:

	https://github.com/jvanasco/insecure_but_secure_enough/blob/main/demo.py
	https://github.com/jvanasco/insecure_but_secure_enough/blob/main/demo_performance.py

Also note that the github source distribution contains tests.

===================


# ToDo:

The timebased providers are largely untested.
* build out the demo and the test suite to support it.

--------------------------------------------------------------------------------

`insecure_but_secure_enough` is released under the MIT license