"""
This package is insecure, but secure enough.

The idea for secure_enough to allow for "autologin cookies" and "instant login"
urls for stupid social web applications.

Two important things to note:

1. You should not use this module for financial transactions or sensitive info.
   That would be egregiously stupid.
2. If you log someone in with this, you should note the login as "insecure" and
   require them to provide a password to view sensitive data or any 'write'
   activity.


This package supports the following schemes for encrypting data:

1. RSA encryption (really!)
2. AES encryption

This package supports the following schemes for signing data:

1. No signing (just serialize)
2. HMAC SHA1 signing
3. HMAC SHA256 signing
4. Request signing, as compatible with Facebook's auth scheme.

The data transformation is as follows:

1. serialize (convert to JSON)
2. base64 encode
3. ? obfuscate
4. ? encrypt
5. ? sign

UNTESTED

* You can create "configuration objects" that accept a timestamp and
  return an appropriate secret/encryption key

===================


There is a bit of documentation in:
    https://github.com/jvanasco/insecure_but_secure_enough/blob/master/insecure_but_secure_enough/__init__.py

The following files give an interactive demo:

    https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo.py
    https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo_performance.py

Also note that the github source distribution contains tests.

===================

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

The encryption I used was a lightweight port from a CPAN module, so it could be
blown away in seconds today.

When i decided to re-implement this, looking around I found a handful of similar
projects - which I've borrowed heavily from.

They include:
    https://github.com/dziegler/django-urlcrypt/blob/master/urlcrypt/lib.py
    http://docs.pylonsproject.org/projects/pyramid/en/1.3-branch/api/session.html#pyramid.session.signed_serialize
    https://developers.facebook.com/docs/authentication/signed_request/

This largely re-implements all of those, along with some other functionality.

Right now, data is a base64_url_encoded version of a string, concatenated list,
or json object (for dicts).  I opted against using pickle, because this format
makes it easier to work with other web technologies (js, php, etc).
this might move to an all json version shortly.

Check demo.py to see an overview of how this works.


# Signed Requests

signed_request_create
and
signed_request_verify

are both handled as @classmethods - along with their support functions.
that means you can call them directly without an object instance.

I built them as @classmethods instead of package functions...
because if you want to extend the options for digest mods, you can just
subclass SecureEnough and overwrite _digestmod to add more providers.

# Encrypting and Signing Cookies

Encrypting cookies currently happens via a 'global' RSA key for an instance of
SecureEnough().  [you provide details for it in the __init__()]

You can use timestamped based app_secrets, obfuscators & rsa keys.

The flow is as such:

1. Subclass the ConfigurationProvider() and overwrite the relevant hooks.
   The requesting mehtods pass a single argument - timestamp - which should
   give you enough to go on.
   Note that app_secret returns a string, while the obfuscator must return an
   object that can `obfuscate` and `deobfuscate`; and rsa_key requires an
   object that can `encrypt` and `decrypt`.
   This libray provides default functionality through wrapper objects you can
   mimic.

2. Instantiate a SecureEnough() object, and register the relevant providers

3. When encrypting data, SecureEnough() will ask the ConfigurationProvider()
   for the approprite keys/secrets for the current time(). When decrypting data,
   SecureEnough() will ask the ConfigurationProvider() for the approprite
   keys/secrets for the time in the cookie/hash (if there is one).

This flow will allow you to easily create a plethora of site secrets and RSA
keys -- as in a new one each day -- which means that while this module is not
actually secure, it is Secure Enough for most web applications.

--------------------------------------------------------------------------------

insecure_but_secure_enough is released under the MIT license
"""
__VERSION__ = "0.1.2"


import base64
import hashlib
import hmac
from time import time
import six

try:
    import simplejson as json
except ImportError:
    import json

# pypi
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA


# ==============================================================================


class Invalid(Exception):
    """Base class you can catch"""

    pass


class InvalidAlgorithm(Invalid):
    """Raised when a secret it too old"""

    pass


class InvalidChecksum(Invalid):
    """the checksums do not match"""

    pass


class InvalidPayload(Invalid):
    """Raised when a payload can't be decoded"""

    pass


class InvalidSignature(Invalid):
    """the signature does not match"""

    pass


class InvalidTimeout(Invalid):
    """Raised when a signature is too old"""

    pass


# ==============================================================================


def _base64_url_encode__py2(bytestring):
    """
    private method for b64 encoding.
    this is just wrapping base64.urlsafe_b64encode,
    to allow for a later switch
    OUTPUT:
        this ALWAYS returns `str`
    """
    padded_b64 = base64.urlsafe_b64encode(bytestring)
    return padded_b64.replace("=", "")  # = is a reserved char


def _base64_url_encode__py3(bytes_):
    """
    private method for b64 encoding.
    this is just wrapping base64.urlsafe_b64encode,
    to allow for a later switch
    OUTPUT:
        this ALWAYS returns `str`
    """
    bytes_ = bytes_.encode() if isinstance(bytes_, str) else bytes_
    padded_b64 = base64.urlsafe_b64encode(bytes_)
    padded_b64 = padded_b64.decode()  # bytes to string
    return padded_b64.replace("=", "")  # = is a reserved char


def split_hashed_format(payload):
    (signed_payload, time_then, hash_received) = payload.split("|")
    time_then = int(float(time_then))
    return (signed_payload, time_then, hash_received)


# ==============================================================================


class AesCipherHolder(object):
    """wraps an AES Symmetric Cipher"""

    _secret = None
    _cipher = None
    _aes_key = None
    _aes_iv = None

    def __init__(self, secret):
        if six.PY3:
            secret = secret.encode() if isinstance(secret, str) else secret
        self._secret = secret

        # compute a 32-byte key
        self._aes_key = hashlib.sha256(secret).digest()
        assert len(self._aes_key) == 32

        # compute a 16-byte initialization vector
        self._aes_iv = hashlib.md5(secret).digest()
        assert len(self._aes_iv) == 16

    def cipher(self):
        # create an AES cipher
        # use CFB mode to avoid padding workflow
        cipher = AES.new(self._aes_key, AES.MODE_CFB, self._aes_iv)
        return cipher

    def encrypt(self, payload_string):
        if six.PY3:
            payload_string = (
                payload_string.encode()
                if isinstance(payload_string, str)
                else payload_string
            )
        return self.cipher().encrypt(payload_string)

    def decrypt(self, bytes_):
        """PY3 requires bytes_"""
        return self.cipher().decrypt(bytes_)


class RsaKeyHolder(object):
    """wraps an RSA key"""

    key = None
    _key_private = None
    _key_private_passphrase = None

    key_length_bytes = None
    block_bytes = None
    cipher = None

    def __init__(self, key_private=None, key_private_passphrase=None):
        self._key_private = key_private
        self._key_private_passphrase = key_private_passphrase
        if self._key_private_passphrase:
            self.key = RSA.importKey(self._key_private, self._key_private_passphrase)
        else:
            self.key = RSA.importKey(self._key_private)
        self.key_length_bytes = self.key.size_in_bytes()
        # from https://bugs.launchpad.net/pycrypto/+bug/328027
        self.block_bytes = self.key_length_bytes - 2 * 20 - 2
        self.cipher = PKCS1_OAEP.new(self.key)

    def encrypt(self, payload_string):
        encrypted_blocks = []
        for block in self._split_string(payload_string, self.block_bytes):
            encrypted_block = self.cipher.encrypt(block)
            encrypted_blocks.append(encrypted_block)
        if six.PY3:
            return b"".join(encrypted_blocks)
        return "".join(encrypted_blocks)

    def decrypt_string(self, payload):
        decrypted_blocks = []
        for block in self._split_string(payload, self.key_length_bytes):
            decrypted_block = self.cipher.decrypt(block)
            decrypted_blocks.append(decrypted_block)
        return "".join(decrypted_blocks)

    def decrypt_bytes(self, payload):
        decrypted_blocks = []
        for block in self._split_bytes(payload, self.key_length_bytes):
            decrypted_block = self.cipher.decrypt(block)
            decrypted_blocks.append(decrypted_block)
        return b"".join(decrypted_blocks)

    if six.PY3:
        # py3 has us working on bytes
        decrypt = decrypt_bytes
    else:
        decrypt = decrypt_string

    def _split_string(self, payload_string, block_size):
        "used in PY2 encoding+decoding and PY3 encoding"
        blocks = []
        start = 0
        while start < len(payload_string):
            block = payload_string[start : (start + block_size)]
            blocks.append(block)
            start += block_size
        if six.PY3:
            return [b.encode() for b in blocks]  # PY3 wants bytes
        return blocks

    def _split_bytes(self, payload_bytes, block_size):
        "only used in PY3 decoding"
        blocks = []
        start = 0
        while start < len(payload_bytes):
            block = payload_bytes[start : (start + block_size)]
            blocks.append(block)
            start += block_size
        return blocks


class Obfuscator(object):
    obfuscation_key = None
    obfuscation_secret = None

    def __init__(self, obfuscation_key, obfuscation_secret):
        self.obfuscation_secret = obfuscation_secret
        if not obfuscation_key:
            if six.PY3:
                obfuscation_secret = (
                    obfuscation_secret.encode()
                    if isinstance(obfuscation_secret, str)
                    else obfuscation_secret
                )
            obfuscation_key = (
                hashlib.sha512(obfuscation_secret).hexdigest()
                + hashlib.sha512(obfuscation_secret[::-1]).hexdigest()
            )
        self.obfuscation_key = obfuscation_key

    def obfuscate(self, text):
        """
        INPUT:
            PY2 - text is `str`
        OUTPUT:
            always returns `str`
        """
        # if six.PY3:
        #    text = text.decode() if not isinstance(text, str) else text
        # copy out our OBFUSCATE_KEY to the length of the text
        key = self.obfuscation_key * (len(text) // len(self.obfuscation_key) + 1)

        # XOR each character from our input
        # with the corresponding character from the key
        xor_gen = (chr(ord(t) ^ ord(k)) for (t, k) in zip(text, key))
        return "".join(xor_gen)

    deobfuscate = obfuscate


class ConfigurationProvider(object):
    """Create and build configuration providers"""

    def app_secret(timestamp):
        """
        for a given timestamp, this should return the appropriate app secret
        """
        return ""

    def obfuscator(timestamp):
        """
        for a given timestamp, this should return the appropriate obfuscator
        """
        obfuscation_secret = ""
        obfuscation_key = ""
        return Obfuscator(obfuscation_key, obfuscation_secret)

    def rsa_key(timestamp):
        """
        for a given timestamp, this should return the appropriate RSA Key
        """
        rsa_key_private = ""
        rsa_key_private_passphrase = ""
        return RsaKeyHolder(
            key_private=rsa_key_private,
            key_private_passphrase=rsa_key_private_passphrase,
        )

    def aes_cipher(timestamp):
        """
        for a given timestamp, this should return the appropriate AES object
        """
        aes_secret = ""
        return AesCipherHolder(aes_secret)


class SecureEnough(object):
    use_aes_encryption = False
    use_obfuscation = False
    use_rsa_encryption = False

    # storage
    _config_provider_aes = None
    _config_provider_app_secret = None
    _config_provider_obfuscation = None
    _config_provider_rsa = None

    _app_secret = None
    _aes_cipher = None
    _obfuscator = None
    _rsa_key = None

    def __init__(
        self,
        config_app_secret=None,
        app_secret="",
        use_aes_encryption=False,
        config_aes=None,
        aes_secret=None,
        use_rsa_encryption=False,
        config_rsa=None,
        rsa_key_private=None,
        rsa_key_private_passphrase=None,
        use_obfuscation=False,
        config_obfuscation=None,
        obfuscation_secret="",
        obfuscation_key=None,
    ):
        if config_app_secret:
            self._config_provider_app_secret = config_app_secret
        else:
            self._app_secret = app_secret

        if use_aes_encryption:
            if not any((config_aes, aes_secret)):
                raise ValueError("Must submit one of: aes_secret, config_aes")
            self.use_aes_encryption = use_aes_encryption
            if config_aes:
                self._config_provider_aes = config_aes
            else:
                self._aes_cipher = AesCipherHolder(aes_secret)

        if use_rsa_encryption:
            self.use_rsa_encryption = use_rsa_encryption
            if config_rsa:
                self._config_provider_rsa = config_rsa
            else:
                self._rsa_key = RsaKeyHolder(
                    key_private=rsa_key_private,
                    key_private_passphrase=rsa_key_private_passphrase,
                )

        if use_obfuscation:
            self.use_obfuscation = use_obfuscation
            if config_obfuscation:
                self._config_provider_obfuscation = config_obfuscation
            else:
                self._obfuscator = Obfuscator(obfuscation_key, obfuscation_secret)

    def app_secret(self, timestamp=None):
        """internal function to return an app secret"""
        if self._config_provider_app_secret:
            return self._config_provider_app_secret.app_secret(timestamp)
        return self._app_secret

    def aes_cipher(self, timestamp=None):
        """internal function to return an aes cipher"""
        if self._config_provider_aes:
            return self._config_provider_aes.aes_cipher(timestamp)
        return self._aes_cipher

    def obfuscator(self, timestamp=None):
        """internal function to return an obfuscator"""
        if self._config_provider_obfuscation:
            return self._config_provider_obfuscation.obfuscator(timestamp)
        return self._obfuscator

    def rsa_key(self, timestamp=None):
        """internal function to return a rsa key"""
        if self._config_provider_rsa:
            return self._config_provider_rsa.rsa_key(timestamp)
        return self._rsa_key

    @classmethod
    def _base64_url_encode(cls, bytes_):
        """
        internal classmethod for b64 encoding.

        INPUT:
            PY2: `str`
            PY3: `bytes`
        OUTPUT:
            this ALWAYS returns `str`
        """
        if six.PY3:
            return _base64_url_encode__py3(bytes_)
        return _base64_url_encode__py2(bytes_)

    @classmethod
    def _base64_url_decode(cls, inp):
        """
        internal classmethod for b64 decoding. this is essentially wrapping
        base64.base64_url_decode, to allow for a later switch

        INPUT:
            PY2: `str`
            PY3: `bytes`
        OUTPUT:
            PY2 str
            PY3 bytes
        """
        padding_factor = (4 - len(inp) % 4) % 4
        inp += "=" * padding_factor
        decoded = base64.urlsafe_b64decode(inp)
        return decoded

    @classmethod
    def _digestmod(cls, algorithm=None):
        """
        internal class and instance method for returning an algoritm function
        """
        if algorithm == "HMAC-SHA256":
            digestmod = hashlib.sha256
        elif algorithm == "HMAC-SHA1":
            digestmod = hashlib.sha1
        else:
            raise InvalidAlgorithm("unsupported algorithm - %s" % algorithm)
        return digestmod

    @classmethod
    def signed_request_create(
        cls, data, secret=None, issued_at=None, algorithm="HMAC-SHA256"
    ):
        """
        classmethod.
        creates a signed token for `data` using `secret`, calculated by
        `algorithm`.  optionally include the `issued_at`
        note that we use a copy of data -- as we need to stick the
        algorithm in there.
        """
        _data = data.copy()
        digestmod = cls._digestmod(algorithm)
        if "algorithm" in _data and _data["algorithm"] != algorithm:
            raise InvalidAlgorithm(
                "`algorithm` defined in payload already, " "and as another format"
            )
        _data["algorithm"] = algorithm
        if issued_at and "issued_at" not in _data:
            _data["issued_at"] = issued_at
        payload = json.dumps(_data)
        if six.PY3:
            payload = payload.encode()  # str to bytes
        payload = cls._base64_url_encode(payload)
        if six.PY3:
            payload = payload.encode()  # str to bytes
            secret = secret.encode() if isinstance(secret, str) else secret
            # hmac.new(secret,msg=payload,digestmod=digestmod).hexdigest()
        signature = hmac.new(secret, msg=payload, digestmod=digestmod).hexdigest()
        if six.PY3:
            return signature + "." + payload.decode()  # bytes to string
        return signature + "." + payload

    @classmethod
    def signed_request_verify(
        cls,
        signed_request=None,
        secret=None,
        timeout=None,
        algorithm="HMAC-SHA256",
        payload_only=False,
    ):
        """
        This is compatible with signed requests from facebook.com
            (https://developers.facebook.com/docs/authentication/signed_request/)

        returns a tuple of (Boolean, Dict), where `Dict` is the payload and
        `Boolean` is `True` or `False` based on an optional `timeout` argument.
        Raises an `Invalid` if a serious error occurs.

        if you submit the kwarg 'payload_only=True', it will only return the
        extracted data.  No boolean will be returned.  If a timeout is also
        submitted, it will return the payload on success and False on failure.
        """
        digestmod = cls._digestmod(algorithm)

        (signature, payload) = signed_request.split(".")

        try:
            decoded_signature = cls._base64_url_decode(signature)
            payload_decoded = cls._base64_url_decode(payload)
            data = json.loads(payload_decoded)
        except json.JSONDecodeError as exc:
            raise InvalidPayload(exc.msg)
        except:
            raise InvalidPayload("Can't decode payload (_base64 error?)")

        if data.get("algorithm").upper() != algorithm:
            raise InvalidAlgorithm(
                "unexpected algorithm.  Wanted %s, Received %s"
                % (algorithm, data.get("algorithm"))
            )

        if six.PY3:
            secret = secret.encode() if isinstance(secret, str) else secret
            payload = payload.encode() if isinstance(payload, str) else secret

        expected_sig = hmac.new(secret, msg=payload, digestmod=digestmod).hexdigest()

        if signature != expected_sig:
            raise InvalidSignature(
                "invalid signature.  signature (%s) != expected_sig (%s)"
                % (signature, expected_sig)
            )

        if timeout:
            time_now = int(time())
            diff = time_now - data["issued_at"]
            if diff > timeout:
                if payload_only:
                    return False
                return (False, data)

        if payload_only:
            return data
        return (True, data)

    def _serialize(self, data):
        """
        internal function to serialize multiple data types for transmission
        input:
            data may be one of: `dict`, `list`, `tuple`, `string`
        output
            PY2: string
            PY3: bytes
        """
        serialized = None
        if isinstance(data, dict):
            serialized = json.dumps(data)
        elif isinstance(data, list) or isinstance(data, tuple):
            serialized = "|".join(data)
            if "|" in serialized:
                raise ValueError("`|` only allowed in dicts")
        elif isinstance(data, str):
            serialized = data
            if "|" in serialized:
                raise ValueError("`|` only allowed in dicts")
        else:
            raise TypeError("invalid type for serialization")
        return serialized

    def _deserialize(self, serialized):
        """internal function to deserialize multiple data types from transmission"""
        data = None
        try:
            data = json.loads(serialized)
        except json.decoder.JSONDecodeError:
            if "|" in serialized:
                data = serialized.split("|")
            else:
                data = serialized
        return data

    def _hmac_for_timestamp(self, payload, timestamp, algorithm="HMAC-SHA1"):
        """
        internal function. calcuates an hmac for a timestamp.
        to accomplish this, we just pad the payload with the given timestamp

        input:
            PY2: payload = string
            PY3: payload = bytes
        returns:
            always returns a string
        """
        digestmod = self._digestmod(algorithm)
        message = "%s||%s" % (payload, timestamp)
        app_secret = self.app_secret(timestamp=timestamp)
        if six.PY3:
            app_secret = (
                app_secret.encode() if isinstance(app_secret, str) else app_secret
            )
            message = message.encode()
            # hmac.new(app_secret,msg=message,digestmod=digestmod).hexdigest()
        return hmac.new(app_secret, msg=message, digestmod=digestmod).hexdigest()

    def encode(self, data, hashtime=True, hmac_algorithm="HMAC-SHA1", time_now=None):
        """
        public method. encodes data.
        time_now should ONLY be used for testing/debugging situations when an
        invalid payload is needed.
        """
        if hmac_algorithm and not hashtime:
            hashtime = True

        # compute the time, which is used for verification
        # and coordinating the right secrets
        if hashtime:
            if time_now is None:
                time_now = int(time())
            else:
                time_now = int(time_now)

        # encode the payload, which serializes it and possibly obfuscates it

        # .. first we serialize it
        # the output of `._serialize()` will be a `str`
        payload = self._serialize(data)

        # .. optionally include lightweight obfuscation
        if self.use_obfuscation:
            # the output of `.obfuscate()` will be a `str`
            payload = self.obfuscator(timestamp=time_now).obfuscate(payload)

        # .. optionally encrypt the payload
        if self.use_rsa_encryption:
            # `.encrypt()` expects a `str` and returns a `str` or `bytes`
            payload = self.rsa_key(timestamp=time_now).encrypt(payload)
        elif self.use_aes_encryption:
            # `.encrypt()` expects a `str` and returns a `str` or `bytes`
            payload = self.aes_cipher(timestamp=time_now).encrypt(payload)

        # finally urlencode it
        payload = self._base64_url_encode(payload)

        # if we're computing time-sensitive keys or expiration, we'll return a compound token
        if hashtime:
            # format compatible with `decode` and `debug_hashtime`
            hash = self._hmac_for_timestamp(payload, time_now, algorithm=hmac_algorithm)
            compound = "%s|%s|%s" % (payload, time_now, hash)
            return compound
        # otherwise, just return the payload
        return payload

    def decode(self, payload, hashtime=True, timeout=None, hmac_algorithm="HMAC-SHA1"):
        """public method. decodes data."""
        if hmac_algorithm and not hashtime:
            hashtime = True

        # if we dont have hashtime support, this needs to be None...
        time_then = None

        # try to validate the hashtime
        if hashtime:
            # format compatible with `encode` and `debug_hashtime`
            (signed_payload, time_then, hash_received) = split_hashed_format(payload)
            hash_expected = self._hmac_for_timestamp(
                signed_payload, time_then, algorithm=hmac_algorithm
            )
            if hash_expected != hash_received:
                raise InvalidChecksum()
            if timeout:
                time_now = int(time())
                # wrap the timeout in an int(float()) to catch floats as strings
                if (time_now - time_then) > int(float(timeout)):
                    raise InvalidTimeout()
            payload = signed_payload

        # decoding is done in reverse of encoding
        # so decrypt, then deobfuscate
        # this always returns bytes
        payload = self._base64_url_decode(payload)

        if self.use_rsa_encryption:
            payload = self.rsa_key(timestamp=time_then).decrypt(payload)
        elif self.use_aes_encryption:
            payload = self.aes_cipher(timestamp=time_then).decrypt(payload)

        if self.use_obfuscation:
            if six.PY3:
                payload = payload.decode()
            payload = self.obfuscator(timestamp=time_then).deobfuscate(payload)

        payload = self._deserialize(payload)

        return payload

    def debug_hashtime(self, payload, timeout=None, hmac_algorithm="HMAC-SHA1"):
        """
        useful for debugging.
        format compatible with `encode` and `decode`
        """
        (signed_payload, time_then, hash_received) = split_hashed_format(payload)

        time_now = int(time())
        checksum_valid = True
        timeout_valid = True
        decoded = None
        decoding_error = None
        try:
            decoded = self.decode(
                payload, hashtime=True, timeout=timeout, hmac_algorithm=hmac_algorithm
            )
        except InvalidChecksum:
            checksum_valid = False
        except InvalidTimeout:
            timeout_valid = False
        except Exception as e:
            decoding_error = e

        return {
            "payload": payload,
            "signed_payload": signed_payload,
            "time_then": time_then,
            "time_now": time_now,
            "hash_received": hash_received,
            "checksum_valid": checksum_valid,
            "decoded": decoded,
            "decoding_error": decoding_error,
        }

    def serialized_plaintext_encode(self, payload):
        return self.encode(payload, hashtime=False, hmac_algorithm=None)

    def serialized_plaintext_decode(self, payload):
        return self.decode(payload, hashtime=False, hmac_algorithm=None)

    def hmac_sha1_encode(self, payload):
        return self.encode(payload, hashtime=True, hmac_algorithm="HMAC-SHA1")

    def hmac_sha1_decode(self, payload):
        return self.decode(payload, hashtime=True, hmac_algorithm="HMAC-SHA1")

    def hmac_sha256_encode(self, payload):
        return self.encode(payload, hashtime=True, hmac_algorithm="HMAC-SHA256")

    def hmac_sha256_decode(self, payload):
        return self.decode(payload, hashtime=True, hmac_algorithm="HMAC-SHA256")
