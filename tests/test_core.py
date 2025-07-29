# stdlib
import datetime
from time import time
from typing import Callable
from typing import Dict
import unittest

# local
import insecure_but_secure_enough
from insecure_but_secure_enough import SecureEnough
from ._utils import aes_secret
from ._utils import app_secret__bytes
from ._utils import app_secret__string
from ._utils import app_secret_wrong__bytes
from ._utils import ConfigurationProvider_app_secret
from ._utils import data
from ._utils import obfuscation_secret
from ._utils import rsa_key_private
from ._utils import rsa_key_private_passphrase

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


def _validate_signed_request_payload(
    decrypted_payload: Dict,
    original_data: Dict,
    algorithm="HMAC-SHA256",
    issued_at=None,
) -> bool:
    # ensure everything ORIGINAL is DECRYPTED
    for i in original_data.keys():
        if i not in decrypted_payload:
            return False
        if original_data[i] != decrypted_payload[i]:
            return False
    additions = {}
    for i in decrypted_payload.keys():
        if i not in original_data:
            additions[i] = decrypted_payload[i]
    return True


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _RSA_Configuration(object):
    """creates RSA factories"""

    def _makeOne_encryption(self):
        encryptionFactory = SecureEnough(
            app_secret=app_secret__bytes,
            use_rsa_encryption=True,
            rsa_key_private=rsa_key_private,
            rsa_key_private_passphrase=rsa_key_private_passphrase,
        )
        return encryptionFactory

    def _makeOne_encryption_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret=app_secret__bytes,
            use_rsa_encryption=True,
            rsa_key_private=rsa_key_private,
            rsa_key_private_passphrase=rsa_key_private_passphrase,
            use_obfuscation=True,
            obfuscation_secret=obfuscation_secret,
        )
        return encryptionFactory


class _AES_Configuration(object):
    """creates AES factories"""

    def _makeOne_encryption(self):
        encryptionFactory = SecureEnough(
            app_secret=app_secret__bytes,
            use_rsa_encryption=True,
            rsa_key_private=rsa_key_private,
            rsa_key_private_passphrase=rsa_key_private_passphrase,
        )
        return encryptionFactory

    def _makeOne_encryption_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret=app_secret__bytes,
            use_aes_encryption=True,
            aes_secret=aes_secret,
            use_obfuscation=True,
            obfuscation_secret=obfuscation_secret,
        )
        return encryptionFactory


class _Obfuscator_Configuration(object):
    """creates AES factories"""

    def _makeOne_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret=app_secret__bytes,
            use_obfuscation=True,
            obfuscation_secret=obfuscation_secret,
        )
        return encryptionFactory


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class TestInvalidArgs(unittest.TestCase):

    def test__invalid_constructor(self):
        with self.assertRaises(ValueError) as cm:
            api1 = SecureEnough(  # noqa: 841
                config_app_secret=ConfigurationProvider_app_secret,
                app_secret=app_secret__bytes,
            )
        self.assertEqual(
            cm.exception.args[0],
            "Supply only one of: `config_app_secret`,  `app_secret`.",
        )

    def test__signed_request_create(self):
        request_data = data.copy()
        with self.assertRaises(ValueError) as cm:
            signed: str = SecureEnough.signed_request_create(  # noqa: F841
                request_data, secret=app_secret__string  # type: ignore[arg-type]
            )
        self.assertEqual(cm.exception.args[0], "`secret` MUST be `bytes`.")

    def test__signed_request_verify(self):
        request_data = data.copy()
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes
        )

        # signed is bytes
        with self.assertRaises(ValueError) as cm1:
            (verified, payload) = SecureEnough.signed_request_verify(
                signed.encode(), secret=app_secret__bytes  # type: ignore[arg-type]
            )
        self.assertEqual(cm1.exception.args[0], "`signed_request` MUST be `str`.")

        # secret is str
        with self.assertRaises(ValueError) as cm2:
            (verified, payload) = SecureEnough.signed_request_verify(
                signed, secret=app_secret__string  # type: ignore[arg-type]
            )
        self.assertEqual(cm2.exception.args[0], "`secret` MUST be `bytes`.")

    def test__signed_request_create__with_timeout(self):
        request_data = data.copy()
        issued_at = int(time())
        with self.assertRaises(ValueError) as cm:
            signed: str = SecureEnough.signed_request_create(  # noqa: F841
                request_data,
                secret=app_secret__string,  # type: ignore[arg-type]
                issued_at=issued_at,
            )
        self.assertEqual(cm.exception.args[0], "`secret` MUST be `bytes`.")

    def test__signed_request_verify__with_timeout(self):
        request_data = data.copy()
        issued_at = int(time())
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes, issued_at=issued_at
        )
        with self.assertRaises(ValueError) as cm:
            (verified, payload) = SecureEnough.signed_request_verify(
                signed,
                secret=app_secret__string,  # type: ignore[arg-type]
                timeout=100,
            )
        self.assertEqual(cm.exception.args[0], "`secret` MUST be `bytes`.")


class _TestInvalidArgs__EncryptionFactory(object):

    assertEqual: Callable
    assertRaises: Callable
    _makeOne_encryption: Callable

    def test__EncryptionFactory__decode(self):

        encryptionFactory = self._makeOne_encryption()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        timeout_bad = datetime.timedelta(days=10).total_seconds()
        encrypted: str = encryptionFactory.encode(
            data, hashtime=True, time_now=issued_at
        )

        with self.assertRaises(ValueError) as cm:
            decrypted = encryptionFactory.decode(  # noqa: F841
                encrypted.encode(), hashtime=True, timeout=timeout_bad
            )
        self.assertEqual(cm.exception.args[0], "`payload` MUST be `str`.")

    def test__EncryptionFactory__debug_hashtime(self):
        encryptionFactory = self._makeOne_encryption()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        encrypted: str = encryptionFactory.encode(
            data, hashtime=True, time_now=issued_at
        )
        with self.assertRaises(ValueError) as cm:
            payload = encryptionFactory.debug_hashtime(encrypted.encode())  # noqa: F841
        self.assertEqual(cm.exception.args[0], "`payload` MUST be `str`.")

    def test__EncryptionFactory__serialized_plaintext_decode(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        # roundtrip
        payload: str = encryptionFactory.serialized_plaintext_encode(request_data)
        with self.assertRaises(ValueError) as cm:
            decoded = encryptionFactory.serialized_plaintext_decode(  # noqa: F841
                payload.encode()
            )
        self.assertEqual(cm.exception.args[0], "`payload` MUST be `str`.")

    def test__EncryptionFactory__hmac_sha1_encode(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        payload: str = encryptionFactory.hmac_sha1_encode(request_data)
        with self.assertRaises(ValueError) as cm:
            decoded = encryptionFactory.hmac_sha1_decode(payload.encode())  # noqa: F841
        self.assertEqual(cm.exception.args[0], "`payload` MUST be `str`.")

    def test__EncryptionFactory__hmac_sha256_encode(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        payload: str = encryptionFactory.hmac_sha256_encode(request_data)
        with self.assertRaises(ValueError) as cm:
            decoded = encryptionFactory.hmac_sha256_decode(  # noqa: F841
                payload.encode()
            )
        self.assertEqual(cm.exception.args[0], "`payload` MUST be `str`.")


class TestInvalidArgs__EncryptionFactory__AES(
    unittest.TestCase,
    _AES_Configuration,
    _TestInvalidArgs__EncryptionFactory,
):
    """
    uses encryptionFactory defined in `_AES_Configuration`
    to run tests defined in `_TestInvalidArgs__EncryptionFactory`
    """

    pass


class TestInvalidArgs__EncryptionFactory__RSA(
    unittest.TestCase,
    _RSA_Configuration,
    _TestInvalidArgs__EncryptionFactory,
):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestInvalidArgs__EncryptionFactory`
    """

    pass


class _TestClassMethods(object):
    assertEqual: Callable
    assertFalse: Callable
    assertTrue: Callable
    assertRaises: Callable

    def test__signed_request_verify(self):
        request_data = data.copy()
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes
        )
        (verified, payload) = SecureEnough.signed_request_verify(
            signed, secret=app_secret__bytes
        )
        self.assertTrue(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))

    def test__signed_request_verify__failure_invalid_signature(self):
        request_data = data.copy()
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes
        )
        self.assertRaises(
            insecure_but_secure_enough.InvalidSignature,
            lambda: SecureEnough.signed_request_verify(
                signed, secret=app_secret_wrong__bytes
            ),
        )

    def test__signed_request_create__invalid_algorithm_a(self):
        request_data = data.copy()
        self.assertRaises(
            insecure_but_secure_enough.InvalidAlgorithm,
            lambda: SecureEnough.signed_request_create(
                request_data, secret=app_secret__bytes, algorithm="md5"
            ),
        )

    def test__signed_request_create__invalid_algorithm_b(self):
        request_data = data.copy()
        request_data["algorithm"] = "md5"
        self.assertRaises(
            insecure_but_secure_enough.InvalidAlgorithm,
            lambda: SecureEnough.signed_request_create(
                request_data, secret=app_secret__bytes
            ),
        )

    def test__signed_request_verify__with_timeout(self):
        request_data = data.copy()
        issued_at = int(time())
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes, issued_at=issued_at
        )
        (verified, payload) = SecureEnough.signed_request_verify(
            signed, secret=app_secret__bytes, timeout=100
        )
        self.assertTrue(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))

    def test__signed_request_verify__with_timeout_failure(self):
        request_data = data.copy()
        # pretend to issue this earlier...
        issued_at = int(time()) - 10000
        signed: str = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes, issued_at=issued_at
        )
        (verified, payload) = SecureEnough.signed_request_verify(
            signed, secret=app_secret__bytes, timeout=1000
        )
        self.assertFalse(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))


class TestClassMethods(unittest.TestCase, _TestClassMethods):
    """
    actually run `_TestClassMethods` tests
    """

    pass


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _TestFactoryMethods_Encrypted_core(object):
    """
    this is just a test harness
    the test runners are:
        TestFactoryMethods_Encrypted_RSA
        TestFactoryMethods_Encrypted_AES
    """

    assertEqual: Callable

    _makeOne_encryption: Callable
    _makeOne_encryption_obfuscation: Callable
    _makeOne_obfuscation: Callable

    def test_encryption_without_hashtime(self):
        encryptionFactory = self._makeOne_encryption()
        encrypted = encryptionFactory.encode(data, hashtime=False)
        decrypted = encryptionFactory.decode(encrypted, hashtime=False)
        self.assertEqual(data, decrypted)

    def test_encryption_with_hashtime(self):
        encryptionFactory = self._makeOne_encryption()
        encrypted = encryptionFactory.encode(data, hashtime=True)
        decrypted = encryptionFactory.decode(encrypted, hashtime=True)
        self.assertEqual(data, decrypted)

    def test_obfuscation_without_hashtime(self):
        encryptionFactory = self._makeOne_obfuscation()
        encrypted = encryptionFactory.encode(data, hashtime=False)
        decrypted = encryptionFactory.decode(encrypted, hashtime=False)
        self.assertEqual(data, decrypted)

    def test_obfuscation_with_hashtime(self):
        encryptionFactory = self._makeOne_obfuscation()
        encrypted = encryptionFactory.encode(data, hashtime=True)
        decrypted = encryptionFactory.decode(encrypted, hashtime=True)
        self.assertEqual(data, decrypted)

    def test_encryption_and_obfuscation_without_hashtime(self):
        encryptionFactory = self._makeOne_encryption_obfuscation()
        encrypted = encryptionFactory.encode(data, hashtime=False)
        decrypted = encryptionFactory.decode(encrypted, hashtime=False)
        self.assertEqual(data, decrypted)

    def test_encryption_and_obfuscation_with_hashtime(self):
        encryptionFactory = self._makeOne_encryption_obfuscation()
        encrypted = encryptionFactory.encode(data, hashtime=True)
        decrypted = encryptionFactory.decode(encrypted, hashtime=True)
        self.assertEqual(data, decrypted)


class TestFactoryMethods_Encrypted_RSA(
    unittest.TestCase,
    _RSA_Configuration,
    _Obfuscator_Configuration,
    _TestFactoryMethods_Encrypted_core,
):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestFactoryMethods_Encrypted_core`
    """

    pass


class TestFactoryMethods_Encrypted_AES(
    unittest.TestCase,
    _AES_Configuration,
    _Obfuscator_Configuration,
    _TestFactoryMethods_Encrypted_core,
):
    """
    uses encryptionFactory defined in `_AES_Configuration`
    to run tests defined in `_TestFactoryMethods_Encrypted_core`
    """

    pass


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class TestVerificationMethods_Generic(unittest.TestCase):
    """
    This is a generic terstrunner
    """

    def test_signed_request_invalid__json(self):
        request_data = data.copy()
        issued_at = int(time())
        signed = SecureEnough.signed_request_create(
            request_data, secret=app_secret__bytes, issued_at=issued_at
        )

        # alter the payload
        signed = signed[::-1]
        self.assertRaises(
            insecure_but_secure_enough.InvalidPayload,
            lambda: SecureEnough.signed_request_verify(
                signed, secret=app_secret__bytes
            ),
        )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _TestVerificationMethods_Encrypted_core(object):
    """
    this is just a test harness
    the test runners are:
        TestVerificationMethods_Encrypted_RSA
        TestVerificationMethods_Encrypted_AES
    """

    assertEqual: Callable
    assertRaises: Callable

    _makeOne_encryption: Callable

    def test_encryption_timeout(self):
        encryptionFactory = self._makeOne_encryption()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        timeout_bad = datetime.timedelta(days=10).total_seconds()
        timeout_good = datetime.timedelta(days=1000).total_seconds()
        encrypted = encryptionFactory.encode(data, hashtime=True, time_now=issued_at)

        self.assertRaises(
            insecure_but_secure_enough.InvalidTimeout,
            lambda: encryptionFactory.decode(
                encrypted, hashtime=True, timeout=timeout_bad
            ),
        )
        decrypted = encryptionFactory.decode(
            encrypted, hashtime=True, timeout=timeout_good
        )
        self.assertEqual(decrypted, data)


class TestVerificationMethods_Encrypted_RSA(
    unittest.TestCase, _RSA_Configuration, _TestVerificationMethods_Encrypted_core
):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestVerificationMethods_Encrypted_core`
    """

    pass


class TestVerificationMethods_Encrypted_AES(
    unittest.TestCase, _AES_Configuration, _TestVerificationMethods_Encrypted_core
):
    """
    uses encryptionFactory defined in `_AES_Configuration`
    to run tests defined in `_TestVerificationMethods_Encrypted_core`
    """

    pass


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _TestEncryptionUtilities_Encrypted_core(object):
    """
    this is just a test harness
    the test runners are:
        TestEncryptionUtilities_Encrypted_RSA
        TestEncryptionUtilities_Encrypted_AES
    """

    assertEqual: Callable
    assertRaises: Callable

    _makeOne_encryption: Callable

    def test_debug_hashtime(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        encrypted = encryptionFactory.encode(data, hashtime=True, time_now=issued_at)

        # ensure we can do a bunch of miscellaneous functions
        payload = encryptionFactory.debug_hashtime(encrypted)
        self.assertEqual(payload["decoded"], request_data)

        payload = encryptionFactory.debug_hashtime(encrypted, timeout=issued_at + 100)
        self.assertEqual(payload["decoded"], request_data)

    def test_serialized_plaintext(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        # roundtrip
        encoded: str = encryptionFactory.serialized_plaintext_encode(request_data)
        payload = encryptionFactory.serialized_plaintext_decode(encoded)
        self.assertEqual(payload, request_data)

    def test_hmac_sha1(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        encoded: str = encryptionFactory.hmac_sha1_encode(request_data)
        payload = encryptionFactory.hmac_sha1_decode(encoded)
        self.assertEqual(payload, request_data)

    def test_hmac_sha256(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        encoded: str = encryptionFactory.hmac_sha256_encode(request_data)
        payload = encryptionFactory.hmac_sha256_decode(encoded)
        self.assertEqual(payload, request_data)


class TestEncryptionUtilities_Encrypted_RSA(
    unittest.TestCase, _RSA_Configuration, _TestEncryptionUtilities_Encrypted_core
):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestEncryptionUtilities_Encrypted_core`
    """

    pass


class TestEncryptionUtilities_Encrypted_AES(
    unittest.TestCase, _AES_Configuration, _TestEncryptionUtilities_Encrypted_core
):
    """
    uses encryptionFactory defined in `_AES_Configuration`
    to run tests defined in `_TestEncryptionUtilities_Encrypted_core`
    """

    pass
