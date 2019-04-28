# our module
import insecure_but_secure_enough
from insecure_but_secure_enough import SecureEnough

# core testing facility
import unittest

# misc...
from time import time
import datetime

rsa_key_private = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,974B87982C450322

d2IYlyCMdJDDGu4C9WHC1wTbdaqogGWcdpmZk17og3j2e7tQ4JTX0nhMTHHPKvPx
44fQ2VfVxDNqcbJL9xMyGLzCjIz4w/PT3lTNTNRRWMHPBKv4oZ9RHIkTGzrX3l+G
KShmXkg1rAhFpiz4eNP7JB/kcZDnSSRE4o+Nvb8w5qirbu8PuJK+kr5u18rC+0OK
i+ylsFyBGIGi4poF0Qw1RExSwfPGcBgTaT9jRIJbf/mtaAf2vu6u94G2lGAw5aUv
hOrUl2Zjo2l+vACGVF7SW+d/dY85+R2BOZhzuYOmlQm/r9MtUYnxn96oesqwrfu9
YKzGzsycqV+B98srU4dJbjKd/7+z5uJnmJtC1fCC8OFJMaZpWKRuImb5vgyOYAMI
BrMfGvi6PjpEE8oHyiiF3KKiaP+HHg+EIaPirNginsHrh3QcdJkbZpefn3NbbfyS
9bsI1P69yH2MLEU/KYSXy9XhmjbwtKUYpyQJOHOmO6J74J7D3rGQl/omG+xSSIX0
r2y2S3Cph/mCv9zVh4ZaishU0VQE/feQNkZzZj/Mr/ck0mqm4kGvP0DJcl8o9XTC
aD1YsUGNmGbQMOt330HXmDFfSo8aH3BpcKU40mBw636HIh8gsNDHguEQxEQDx1La
cxpcKi/x4bktCW7JBPC/r9aZOy7wNr9vUvKBK8y3WbcDECNbm/puqfAUM5ljOlIA
kZSdMQIc9jwAuyrwR4TvcSWHmzIN4P1l6R2KL31ViQxwokrdFpL46eUovIiG69sG
qLMvdCqApHakhoed8JcllCws7ulDomv0L88KWCCtrvQQSb4l+PgNyQ==
-----END RSA PRIVATE KEY-----
"""
rsa_key_private_passphrase = """tweet"""
rsa_key_public = None


aes_secret = 'insecure_but_secure_enough'

data = {'hello': 'world!'}
app_secret = '517353cr37'
app_secret_wrong = 'not-the-app-secret'


def _validate_signed_request_payload(decrypted_payload, original_data, algorithm='HMAC-SHA256', issued_at=None):
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
            app_secret = app_secret,
            use_rsa_encryption = True,
            rsa_key_private = rsa_key_private,
            rsa_key_private_passphrase = rsa_key_private_passphrase
        )
        return encryptionFactory

    def _makeOne_encryption_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret = app_secret,
            use_rsa_encryption = True,
            rsa_key_private = rsa_key_private,
            rsa_key_private_passphrase = rsa_key_private_passphrase,
            use_obfuscation = True,
            obfuscation_secret = app_secret,
        )
        return encryptionFactory


class _AES_Configuration(object):
    """creates AES factories"""

    def _makeOne_encryption(self):
        encryptionFactory = SecureEnough(
            app_secret = app_secret,
            use_rsa_encryption = True,
            rsa_key_private = rsa_key_private,
            rsa_key_private_passphrase = rsa_key_private_passphrase
        )
        return encryptionFactory

    def _makeOne_encryption_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret = app_secret,
            use_aes_encryption = True,
            aes_secret = aes_secret,
            use_obfuscation = True,
            obfuscation_secret = app_secret,
        )
        return encryptionFactory


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class TestClassMethods(unittest.TestCase):

    def test_signed_request_create_and_verify(self):
        request_data = data.copy()
        signed = SecureEnough.signed_request_create(request_data, secret=app_secret)
        (verified, payload) = SecureEnough.signed_request_verify(signed, secret=app_secret)
        self.assertTrue(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))

    def test_signed_request_verify_failure_invalid_signature(self):
        request_data = data.copy()
        signed = SecureEnough.signed_request_create(request_data, secret=app_secret)
        self.assertRaises(
            insecure_but_secure_enough.InvalidSignature,
            lambda: SecureEnough.signed_request_verify(signed, secret=app_secret_wrong)
        )

    def test_signed_request_verify_failure_invalid_algoritm(self):
        request_data = data.copy()
        self.assertRaises(
            insecure_but_secure_enough.InvalidAlgorithm,
            lambda: SecureEnough.signed_request_create(request_data, secret=app_secret, algorithm='md5')
        )

    def test_signed_request_create_invalid_algoritm(self):
        request_data = data.copy()
        request_data['algorithm'] = 'md5'
        self.assertRaises(
            insecure_but_secure_enough.InvalidAlgorithm,
            lambda: SecureEnough.signed_request_create(request_data, secret=app_secret)
        )

    def test_signed_request_create_and_verify_with_timeout(self):
        request_data = data.copy()
        issued_at = int(time())
        signed = SecureEnough.signed_request_create(request_data, secret=app_secret, issued_at=issued_at)
        (verified, payload) = SecureEnough.signed_request_verify(signed, secret=app_secret, timeout=100)
        self.assertTrue(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))

    def test_signed_request_create_and_verify_with_timeout_failure(self):
        request_data = data.copy()
        # pretend to issue this earlier...
        issued_at = int(time()) - 10000
        signed = SecureEnough.signed_request_create(request_data, secret=app_secret, issued_at=issued_at)
        (verified, payload) = SecureEnough.signed_request_verify(signed, secret=app_secret, timeout=1000)
        self.assertFalse(verified)
        self.assertTrue(_validate_signed_request_payload(payload, request_data))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _TestFactoryMethods_Encrypted_core(object):
    """
    this is just a test harness
    the test runners are:
        TestFactoryMethods_Encrypted_RSA
        TestFactoryMethods_Encrypted_AES
    """

    def _makeOne_obfuscation(self):
        encryptionFactory = SecureEnough(
            app_secret = app_secret,
            use_obfuscation = True,
            obfuscation_secret = app_secret,
        )
        return encryptionFactory

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


class TestFactoryMethods_Encrypted_RSA(unittest.TestCase, _RSA_Configuration, _TestFactoryMethods_Encrypted_core,):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestFactoryMethods_Encrypted_core`
    """
    pass


class TestFactoryMethods_Encrypted_AES(unittest.TestCase, _AES_Configuration, _TestFactoryMethods_Encrypted_core, ):
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
        signed = SecureEnough.signed_request_create(request_data, secret=app_secret, issued_at=issued_at)

        # alter the payload
        signed = signed[::-1]
        self.assertRaises(
            insecure_but_secure_enough.InvalidPayload,
            lambda: SecureEnough.signed_request_verify(signed, secret=app_secret)
        )


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class _TestVerificationMethods_Encrypted_core(object):
    """
    this is just a test harness
    the test runners are:
        TestVerificationMethods_Encrypted_RSA
        TestVerificationMethods_Encrypted_AES
    """

    def test_encryption_timeout(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        timeout_bad = datetime.timedelta(days=10).total_seconds()
        timeout_good = datetime.timedelta(days=1000).total_seconds()
        encrypted = encryptionFactory.encode(data, hashtime=True, time_now=issued_at)
        
        self.assertRaises(
            insecure_but_secure_enough.InvalidTimeout,
            lambda: encryptionFactory.decode(encrypted, hashtime=True, timeout=timeout_bad)
        )
        decrypted = encryptionFactory.decode(encrypted, hashtime=True, timeout=timeout_good)


class TestVerificationMethods_Encrypted_RSA(unittest.TestCase, _RSA_Configuration, _TestVerificationMethods_Encrypted_core):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestVerificationMethods_Encrypted_core`
    """
    pass



class TestVerificationMethods_Encrypted_AES(unittest.TestCase, _AES_Configuration, _TestVerificationMethods_Encrypted_core):
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

    def test_debug_hashtime(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        issued_at = int(time()) - datetime.timedelta(days=100).total_seconds()
        encrypted = encryptionFactory.encode(data, hashtime=True, time_now=issued_at)

        # ensure we can do a bunch of miscellaneous functions
        payload = encryptionFactory.debug_hashtime(encrypted)
        self.assertEqual(payload['decoded'], request_data)

        payload = encryptionFactory.debug_hashtime(encrypted, timeout=issued_at+100)
        self.assertEqual(payload['decoded'], request_data)

    def test_serialized_plaintext(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        # roundtrip
        payload = encryptionFactory.serialized_plaintext_encode(request_data)
        payload = encryptionFactory.serialized_plaintext_decode(payload)
        self.assertEqual(payload, request_data)

    def test_hmac_sha1(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        payload = encryptionFactory.hmac_sha1_encode(request_data)
        payload = encryptionFactory.hmac_sha1_decode(payload)
        self.assertEqual(payload, request_data)

    def test_hmac_sha256(self):
        encryptionFactory = self._makeOne_encryption()
        request_data = data.copy()
        payload = encryptionFactory.hmac_sha256_encode(request_data)
        payload = encryptionFactory.hmac_sha256_decode(payload)
        self.assertEqual(payload, request_data)


class TestEncryptionUtilities_Encrypted_RSA(unittest.TestCase, _RSA_Configuration, _TestEncryptionUtilities_Encrypted_core):
    """
    uses encryptionFactory defined in `_RSA_Configuration`
    to run tests defined in `_TestEncryptionUtilities_Encrypted_core`
    """
    pass



class TestEncryptionUtilities_Encrypted_AES(unittest.TestCase, _AES_Configuration, _TestEncryptionUtilities_Encrypted_core):
    """
    uses encryptionFactory defined in `_AES_Configuration`
    to run tests defined in `_TestEncryptionUtilities_Encrypted_core`
    """
    pass
