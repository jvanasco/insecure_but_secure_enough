# stdlib
import base64
import hashlib
import hmac
import json
import os
from time import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from typing_extensions import Protocol


# ==============================================================================

__VERSION__ = "0.3.0"

TYPE_decoded = Union[None, str, Dict, List]

# Monkeypatch this to require strict inputs
ALLOW_LAX_INPUTS = False

# enable this to PRINT (not log) debug information.
DEBUG_FUNC = bool(int(os.getenv("IBSE_DEBUG_FUNC", "0")))


# import warnings
#
# def warn_future_LAX_INPUTS(message: str) -> None:
#     message += (
#        " `ALLOW_LAX_INPUTS` is currently enabled by dfault, but will be removed."
#    )
#    warnings.warn(message, FutureWarning, stacklevel=2)


class _CipherInterface(Protocol):
    def encrypt(self, ciphertext: bytes) -> bytes: ...  # noqa: E704

    def decrypt(self, message: bytes) -> bytes: ...  # noqa: E704


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


def split_hashed_format(
    payload: str,
) -> Tuple[str, int, str]:
    if not isinstance(payload, str):
        raise ValueError("`payload` MUST be `str`.")
    (signed_payload, time_then, hash_received) = payload.split("|")
    _time_then = int(float(time_then))
    return (signed_payload, _time_then, hash_received)


# ==============================================================================


class AesCipherHolder(object):
    """wraps an AES Symmetric Cipher"""

    _secret: bytes
    _aes_key: bytes
    _aes_iv: bytes

    def __init__(
        self,
        secret: bytes,
    ):
        if not isinstance(secret, bytes):
            raise ValueError("`secret` MUST be `bytes`.")
        self._secret = secret

        # compute a 32-byte key
        self._aes_key = hashlib.sha256(secret).digest()
        assert len(self._aes_key) == 32

        # compute a 16-byte initialization vector
        self._aes_iv = hashlib.md5(secret).digest()
        assert len(self._aes_iv) == 16

    def cipher(self) -> Any:
        # create an AES cipher
        # use CFB mode to avoid padding workflow
        cipher = AES.new(self._aes_key, AES.MODE_CFB, self._aes_iv)
        return cipher

    def encrypt(
        self,
        payload: bytes,
    ) -> bytes:
        _encrypted = self.cipher().encrypt(payload)
        return _encrypted

    def decrypt(
        self,
        payload: bytes,
    ) -> bytes:
        _decrypted = self.cipher().decrypt(payload)
        return _decrypted


class RsaKeyHolder(object):
    """wraps an RSA key"""

    key: RSA.RsaKey
    _key_private: str
    _key_private_passphrase: Optional[str]
    key_length_bytes: int
    block_bytes: int
    cipher: _CipherInterface

    def __init__(
        self,
        key_private: str,
        key_private_passphrase: Optional[str] = None,
    ):
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

    def encrypt(
        self,
        payload: bytes,
    ) -> bytes:
        encrypted_blocks: List[bytes] = []
        for block in self._split_bytes(payload, self.block_bytes):
            encrypted_block = self.cipher.encrypt(block)
            encrypted_blocks.append(encrypted_block)
        return b"".join(encrypted_blocks)

    def decrypt(
        self,
        payload: bytes,
    ) -> bytes:
        decrypted_blocks: List[bytes] = []
        for block in self._split_bytes(payload, self.key_length_bytes):
            decrypted_block = self.cipher.decrypt(block)
            decrypted_blocks.append(decrypted_block)
        return b"".join(decrypted_blocks)

    def _split_string(
        self,
        payload_string: str,
        block_size: int,
    ) -> List[bytes]:
        "used in PY2 encoding+decoding and PY3 encoding"
        blocks = []
        start = 0
        while start < len(payload_string):
            block = payload_string[start : (start + block_size)]  # noqa: E203
            blocks.append(block)
            start += block_size
        return [b.encode() for b in blocks]  # PY3 wants bytes

    def _split_bytes(
        self,
        payload_bytes: bytes,
        block_size: int,
    ) -> List[bytes]:
        "only used in PY3 decoding"
        blocks = []
        start = 0
        while start < len(payload_bytes):
            block = payload_bytes[start : (start + block_size)]  # noqa: E203
            blocks.append(block)
            start += block_size
        return blocks


class Obfuscator(object):
    # actually used by our default Obfuscator
    obfuscation_key: str
    # only used to generate the Obfuscator key
    obfuscation_secret: Optional[bytes] = None

    def __init__(
        self,
        obfuscation_key: Optional[str] = None,
        obfuscation_secret: Optional[bytes] = None,
    ):
        if all((obfuscation_key, obfuscation_secret)) or not any(
            (obfuscation_key, obfuscation_secret)
        ):
            raise ValueError(
                "Submit one and only one of: `obfuscation_key` or `obfuscation_secret`."
            )
        if obfuscation_secret:
            if not isinstance(obfuscation_secret, bytes):
                raise ValueError("`obfuscation_secret` MUST be `bytes`.")
            self.obfuscation_secret = obfuscation_secret

        # generate the `obfuscation_key` if needed
        if not obfuscation_key:
            if not obfuscation_secret:
                raise ValueError("`obfuscation_secret` is required.")
            obfuscation_key = (
                hashlib.sha512(obfuscation_secret).hexdigest()
                + hashlib.sha512(obfuscation_secret[::-1]).hexdigest()
            )
        self.obfuscation_key = obfuscation_key

    def obfuscate(
        self,
        text: str,
    ) -> str:
        """
        Generate obfuscated text
        """
        # copy out our OBFUSCATE_KEY to the length of the text
        key = self.obfuscation_key * (len(text) // len(self.obfuscation_key) + 1)

        if __debug__:
            if DEBUG_FUNC:
                print("============== obfuscate ==============")
                print("* text:", type(text), text)
                print("* key:", type(key), key)

        # XOR each character from our input
        # with the corresponding character from the key
        xor_gen = (chr(ord(t) ^ ord(k)) for (t, k) in zip(text, key))
        result = "".join(xor_gen)

        return result

    deobfuscate = obfuscate


class ConfigurationProvider(object):
    """Create and build configuration providers.
    This class defines an interface that can be subclassed.
    """

    def app_secret(
        self,
        timestamp: Optional[int] = None,
    ) -> bytes:
        """
        for a given timestamp, this should return the appropriate app secret
        """
        return b""

    def obfuscator(
        self,
        timestamp: Optional[int] = None,
    ) -> Obfuscator:
        """
        for a given timestamp, this should return the appropriate Obfuscator
        """
        obfuscation_secret = b""
        obfuscation_key = ""
        return Obfuscator(obfuscation_key, obfuscation_secret)

    def rsa_key(
        self,
        timestamp: Optional[int] = None,
    ) -> RsaKeyHolder:
        """
        for a given timestamp, this should return the appropriate RSA Key Holder
        """
        rsa_key_private = ""
        rsa_key_private_passphrase = ""
        return RsaKeyHolder(
            key_private=rsa_key_private,
            key_private_passphrase=rsa_key_private_passphrase,
        )

    def aes_cipher(
        self,
        timestamp: Optional[int] = None,
    ) -> AesCipherHolder:
        """
        for a given timestamp, this should return the appropriate AES Cipher Holder
        """
        aes_secret = b""
        return AesCipherHolder(aes_secret)


class SecureEnough(object):
    use_aes_encryption: bool = False
    use_obfuscation: bool = False
    use_rsa_encryption: bool = False

    # storage
    _ConfigurationProvider_app_secret: Optional[ConfigurationProvider] = None
    _ConfigurationProvider_aes: Optional[ConfigurationProvider] = None
    _ConfigurationProvider_obfuscation: Optional[ConfigurationProvider] = None
    _ConfigurationProvider_rsa: Optional[ConfigurationProvider] = None

    # Holders
    _app_secret: Optional[bytes] = None
    _AesCipherHolder: Optional[AesCipherHolder] = None
    _Obfuscator = None
    _RsaKeyHolder = None

    def __init__(
        self,
        # ConfigurationProvider
        config_app_secret: Optional[ConfigurationProvider] = None,
        config_aes: Optional[ConfigurationProvider] = None,
        config_rsa: Optional[ConfigurationProvider] = None,
        config_obfuscation: Optional[ConfigurationProvider] = None,
        # app secret
        app_secret: Optional[bytes] = None,
        # aes
        use_aes_encryption: bool = False,
        aes_secret: Optional[bytes] = None,
        # rsa
        use_rsa_encryption: bool = False,
        rsa_key_private: Optional[str] = None,
        rsa_key_private_passphrase: Optional[str] = None,
        # obfuscation
        use_obfuscation: bool = False,
        obfuscation_secret: Optional[bytes] = None,
        obfuscation_key: Optional[str] = None,
    ):
        # app serect
        if config_app_secret and app_secret:
            raise ValueError("Supply only one of: `config_app_secret`,  `app_secret`.")

        # we might not even have either; e.g. obsfuscator uses it's own key/secret
        if config_app_secret:
            if not isinstance(config_app_secret, ConfigurationProvider):
                raise ValueError("`config_app_secret` MUST be `ConfigurationProvider`.")
            self.ConfigurationProvider = config_app_secret
        elif app_secret:
            if not isinstance(app_secret, bytes):
                raise ValueError("`app_secret` MUST be `bytes`.")
            self._app_secret = app_secret

        # aes
        if use_aes_encryption:
            if not any((config_aes, aes_secret)) or all((config_aes, aes_secret)):
                raise ValueError("Must submit only one of: `aes_secret`, `config_aes`.")
            self.use_aes_encryption = use_aes_encryption
            if config_aes:
                if not isinstance(config_aes, ConfigurationProvider):
                    raise ValueError("`config_aes` MUST be `ConfigurationProvider`.")
                self._ConfigurationProvider_aes = config_aes
            else:
                if not isinstance(aes_secret, bytes):
                    raise ValueError("`aes_secret` MUST be `bytes`.")
                if TYPE_CHECKING:
                    assert aes_secret is not None
                self._AesCipherHolder = AesCipherHolder(aes_secret)

        if use_rsa_encryption:
            if not any((config_rsa, rsa_key_private)) or all(
                (config_rsa, rsa_key_private)
            ):
                raise ValueError(
                    "Must submit only one of: `config_rsa`, `rsa_key_private`."
                )
            self.use_rsa_encryption = use_rsa_encryption
            if config_rsa:
                if not isinstance(config_rsa, ConfigurationProvider):
                    raise ValueError("`config_rsa` MUST be `ConfigurationProvider`.")
                self._ConfigurationProvider_rsa = config_rsa
            else:
                if TYPE_CHECKING:
                    assert rsa_key_private is not None
                self._RsaKeyHolder = RsaKeyHolder(
                    key_private=rsa_key_private,
                    key_private_passphrase=rsa_key_private_passphrase,
                )

        if use_obfuscation:
            if all((obfuscation_key, obfuscation_secret)) or not any(
                (obfuscation_key, obfuscation_secret)
            ):
                raise ValueError(
                    "Must submit only one of: `obfuscation_secret`, `obfuscation_key`."
                )
            if obfuscation_secret:
                if not isinstance(obfuscation_secret, bytes):
                    raise ValueError("`obfuscation_secret` MUST be `bytes`.")
            self.use_obfuscation = use_obfuscation
            if config_obfuscation:
                if not isinstance(config_obfuscation, ConfigurationProvider):
                    raise ValueError(
                        "`config_obfuscation` MUST be `ConfigurationProvider`."
                    )
                self._ConfigurationProvider_obfuscation = config_obfuscation
            else:
                self._Obfuscator = Obfuscator(obfuscation_key, obfuscation_secret)

    def app_secret(
        self,
        timestamp: Optional[int] = None,
    ) -> bytes:
        """internal function to return an app secret"""
        if self._ConfigurationProvider_app_secret:
            return self._ConfigurationProvider_app_secret.app_secret(timestamp)
        if self._app_secret:
            return self._app_secret
        raise ValueError("No provider configured for: `.app_secret`.")

    def aes_cipher(
        self,
        timestamp: Optional[int] = None,
    ) -> AesCipherHolder:
        """internal function to return an aes cipher"""
        if self._ConfigurationProvider_aes:
            return self._ConfigurationProvider_aes.aes_cipher(timestamp)
        if self._AesCipherHolder:
            return self._AesCipherHolder
        raise ValueError("No provider configured for: `.aes_cipher`.")

    def obfuscator(
        self,
        timestamp: Optional[int] = None,
    ) -> Obfuscator:
        """internal function to return an obfuscator"""
        if self._ConfigurationProvider_obfuscation:
            return self._ConfigurationProvider_obfuscation.obfuscator(timestamp)
        if self._Obfuscator:
            return self._Obfuscator
        raise ValueError("No provider configured for: `.obfuscator`.")

    def rsa_key(
        self,
        timestamp: Optional[int] = None,
    ) -> RsaKeyHolder:
        """internal function to return a rsa key"""
        if self._ConfigurationProvider_rsa:
            return self._ConfigurationProvider_rsa.rsa_key(timestamp)
        if self._RsaKeyHolder:
            return self._RsaKeyHolder
        raise ValueError("No provider configured for: `.rsa_key`.")

    @classmethod
    def _base64_url_encode(
        cls,
        bytes_: bytes,
    ) -> str:
        """
        internal classmethod for b64 encoding.

        INPUT:
            PY3: `bytes`
        OUTPUT:
            this ALWAYS returns `str`
        """
        # bytes_ = bytes_.encode() if isinstance(bytes_, str) else bytes_
        padded_b64 = base64.urlsafe_b64encode(bytes_)
        padded_b64_str = padded_b64.decode()  # bytes to string
        return padded_b64_str.replace("=", "")  # = is a reserved char

    @classmethod
    def _base64_url_decode(
        cls,
        payload: str,
    ) -> bytes:
        """
        internal classmethod for b64 decoding. this is essentially wrapping
        base64.base64_url_decode, to allow for a later switch
        """
        if not isinstance(payload, str):
            raise ValueError("`payload` MUST be `str`.")
        padding_factor = (4 - len(payload) % 4) % 4
        payload += "=" * padding_factor
        decoded = base64.urlsafe_b64decode(payload)
        return decoded

    @classmethod
    def _digestmod(
        cls,
        algorithm: str,
    ) -> Callable:
        """
        internal class and instance method for returning an algorithm function
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
        cls,
        data: Dict,
        secret: bytes,
        issued_at: Optional[int] = None,
        algorithm: str = "HMAC-SHA256",
    ) -> str:
        """
        classmethod.
        creates a signed token for `data` using `secret`, calculated by
        `algorithm`.  optionally include the `issued_at`
        note that we use a copy of data -- as we need to stick the
        algorithm in there.
        """
        if not isinstance(secret, bytes):
            raise ValueError("`secret` MUST be `bytes`.")
        _data = data.copy()
        if "algorithm" in _data and _data["algorithm"] != algorithm:
            raise InvalidAlgorithm(
                "`algorithm` defined in payload already, " "and as another format"
            )
        _data["algorithm"] = algorithm
        if issued_at and "issued_at" not in _data:
            _data["issued_at"] = issued_at

        _digestmod = cls._digestmod(algorithm)
        payload = json.dumps(_data)
        payload = cls._base64_url_encode(payload.encode())
        # hmac.new(secret,msg=payload,digestmod=_digestmod).hexdigest()
        signature = hmac.new(
            secret, msg=payload.encode(), digestmod=_digestmod
        ).hexdigest()
        return signature + "." + payload

    @classmethod
    def signed_request_verify(
        cls,
        signed_request: str,
        secret: bytes,
        timeout: Optional[int] = None,
        algorithm: str = "HMAC-SHA256",
    ) -> Tuple[bool, Dict]:
        """
        This is compatible with signed requests from facebook.com
            (https://developers.facebook.com/docs/authentication/signed_request/)

        returns a tuple of (Boolean, Dict), where `Dict` is the payload and
        `Boolean` is `True` or `False` based on an optional `timeout` argument.
        Raises an `Invalid` if a serious error occurs.
        """
        if not isinstance(signed_request, str):
            raise ValueError("`signed_request` MUST be `str`.")
        if not isinstance(secret, bytes):
            raise ValueError("`secret` MUST be `bytes`.")
        signature: str
        payload: str
        (signature, payload) = signed_request.split(".")
        digestmod = cls._digestmod(algorithm)
        try:
            # decoded_signature = cls._base64_url_decode(signature)
            payload_decoded = cls._base64_url_decode(payload)
            data = json.loads(payload_decoded)
        except json.JSONDecodeError as exc:
            raise InvalidPayload(exc.msg)
        except Exception:
            raise InvalidPayload("Can't decode payload (_base64 error?).")

        if data.get("algorithm").upper() != algorithm:
            raise InvalidAlgorithm(
                "unexpected algorithm.  Wanted %s, Received %s"
                % (algorithm, data.get("algorithm"))
            )

        _payload: bytes = payload.encode()

        expected_sig = hmac.new(secret, msg=_payload, digestmod=digestmod).hexdigest()

        if signature != expected_sig:
            raise InvalidSignature(
                "invalid signature.  signature (%s) != expected_sig (%s)"
                % (signature, expected_sig)
            )

        if timeout:
            time_now = int(time())
            diff = time_now - data["issued_at"]
            if diff > timeout:
                return (False, data)

        return (True, data)

    def _serialize(
        self,
        data: Union[Dict, List, Tuple, str],
    ) -> str:
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
                raise ValueError("`|` only allowed in dict.")
        elif isinstance(data, str):
            serialized = data
            if "|" in serialized:
                raise ValueError("`|` only allowed in dict.")
        else:
            raise TypeError("invalid type for serialization.")
        return serialized

    def _deserialize(
        self,
        serialized: str,
    ) -> TYPE_decoded:
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

    def _hmac_for_timestamp(
        self,
        payload: bytes,
        timestamp: int,
        algorithm: str = "HMAC-SHA1",
    ) -> str:
        """
        internal function. calcuates an hmac for a timestamp.
        to accomplish this, we just pad the payload with the given timestamp

        input:
            PY3: payload = bytes
        returns:
            always returns a string
        """
        digestmod = self._digestmod(algorithm)
        message = "%s||%s" % (payload.decode(), timestamp)
        app_secret = self.app_secret(timestamp=timestamp)  # bytes
        # hmac.new(app_secret,msg=message,digestmod=digestmod).hexdigest()
        return hmac.new(
            app_secret, msg=message.encode(), digestmod=digestmod
        ).hexdigest()

    def encode(
        self,
        data: Union[Dict, List, Tuple, str],
        hashtime: bool = True,
        hmac_algorithm: Optional[str] = "HMAC-SHA1",
        time_now: Optional[int] = None,
    ) -> str:
        """
        public method. encodes data::string.
        time_now should ONLY be used for testing/debugging situations when an
        invalid payload is needed.
        time_now will be cast to an int
        """
        if __debug__:
            if DEBUG_FUNC:
                print("============== encode ==============")
                print("* data:", type(data), data)
                print("* hashtime:", type(hashtime), hashtime)
                print("* time_now:", type(time_now), time_now)
                print("* hmac_algorithm:", type(hmac_algorithm), hmac_algorithm)

        # compute the time, which is used for verification
        # and coordinating the right secrets
        if hashtime:
            if not hmac_algorithm:
                raise ValueError(
                    "Must supply `hmac_algorithm` if `hashtime` requested."
                )
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
            # deobfuscate == obfuscate: str -> str
            payload = self.obfuscator(timestamp=time_now).obfuscate(payload)

        # byte operations
        _payload = payload.encode()
        # .. optionally encrypt the payload
        if self.use_rsa_encryption or self.use_aes_encryption:
            if self.use_rsa_encryption:
                # `.encrypt()` expects a `bytes` and returns `bytes`
                _payload = self.rsa_key(timestamp=time_now).encrypt(_payload)
            elif self.use_aes_encryption:
                # `.encrypt()` expects a `bytes` and returns `bytes`
                _payload = self.aes_cipher(timestamp=time_now).encrypt(_payload)
        # finally urlencode it: bytes->str
        payload = self._base64_url_encode(_payload)

        # if we're computing time-sensitive keys or expiration, we'll return a compound token
        if hashtime:
            if TYPE_CHECKING:
                assert time_now is not None
                assert hmac_algorithm is not None
            # format compatible with `decode` and `debug_hashtime`
            hashed = self._hmac_for_timestamp(
                payload.encode(), time_now, algorithm=hmac_algorithm
            )
            compound = "%s|%s|%s" % (payload, time_now, hashed)
            return compound

        # otherwise, just return the payload
        return payload

    def decode(
        self,
        payload: str,
        hashtime: bool = True,
        timeout: Optional[int] = None,
        hmac_algorithm: Optional[str] = "HMAC-SHA1",
    ) -> TYPE_decoded:
        """public method. decodes data."""
        if __debug__:
            if DEBUG_FUNC:
                print("============== decode ==============")
                print("* payload:", type(payload), payload)
                print("* hashtime:", type(hashtime), hashtime)
                print("* timeout:", type(timeout), timeout)
                print("* hmac_algorithm:", type(hmac_algorithm), hmac_algorithm)

        # if we dont have hashtime support, this needs to be None...
        time_then: Optional[int] = None

        if hashtime:
            if not hmac_algorithm:
                raise ValueError(
                    "Must supply `hmac_algorithm` if `hashtime` requested."
                )

        # try to validate the hashtime
        if hashtime:
            if TYPE_CHECKING:
                assert hmac_algorithm is not None
            # format compatible with `encode` and `debug_hashtime`
            (signed_payload, time_then, hash_received) = split_hashed_format(payload)
            hash_expected = self._hmac_for_timestamp(
                signed_payload.encode(), time_then, algorithm=hmac_algorithm
            )
            if hash_expected != hash_received:
                raise InvalidChecksum()
            if timeout:
                time_now = int(time())
                # wrap the timeout in an int(float()) to catch floats as strings
                if (time_now - time_then) > int(float(timeout)):
                    raise InvalidTimeout()
            payload = signed_payload

        # decodes into bytes: bytes/str -> bytes
        _payload = self._base64_url_decode(payload)

        # decoding is done in reverse of encoding
        # so decrypt, then deobfuscate
        # this always returns bytes
        if self.use_rsa_encryption or self.use_aes_encryption:
            # decrypt: bytes->bytes
            if self.use_rsa_encryption:
                _payload = self.rsa_key(timestamp=time_then).decrypt(_payload)
            elif self.use_aes_encryption:
                _payload = self.aes_cipher(timestamp=time_then).decrypt(_payload)

        # to string
        payload = _payload.decode()
        if self.use_obfuscation:
            # deobfuscate == obfuscate: str -> str
            payload = self.obfuscator(timestamp=time_then).deobfuscate(payload)

        # str to any
        deserialized = self._deserialize(payload)
        return deserialized

    def debug_hashtime(
        self,
        payload: str,
        timeout: Optional[int] = None,
        hmac_algorithm: str = "HMAC-SHA1",
    ) -> Dict:
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

        rval: Dict = {
            "payload": payload,
            "signed_payload": signed_payload,
            "time_then": time_then,
            "time_now": time_now,
            "timeout_valid": timeout_valid,
            "hash_received": hash_received,
            "checksum_valid": checksum_valid,
            "decoded": decoded,
            "decoding_error": decoding_error,
        }
        return rval

    def serialized_plaintext_encode(self, payload: str) -> str:
        return self.encode(payload, hashtime=False, hmac_algorithm=None)

    def serialized_plaintext_decode(self, payload: str) -> TYPE_decoded:
        return self.decode(payload, hashtime=False, hmac_algorithm=None)

    def hmac_sha1_encode(self, payload: str) -> str:
        return self.encode(payload, hashtime=True, hmac_algorithm="HMAC-SHA1")

    def hmac_sha1_decode(self, payload: str) -> TYPE_decoded:
        return self.decode(payload, hashtime=True, hmac_algorithm="HMAC-SHA1")

    def hmac_sha256_encode(self, payload: str) -> str:
        return self.encode(payload, hashtime=True, hmac_algorithm="HMAC-SHA256")

    def hmac_sha256_decode(self, payload: str) -> TYPE_decoded:
        return self.decode(payload, hashtime=True, hmac_algorithm="HMAC-SHA256")
