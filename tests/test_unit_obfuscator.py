# stdlib
import unittest

# local
from insecure_but_secure_enough import Obfuscator
from insecure_but_secure_enough import SecureEnough
from ._utils import app_secret__bytes
from ._utils import data_string
from ._utils import data_string_encoded
from ._utils import data_string_obfuscated
from ._utils import obfuscation_key
from ._utils import obfuscation_secret

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


class Test_Obfuscator(unittest.TestCase):
    def test_create(self):
        # can we make an Obfuscator correctly?

        with self.assertRaises(ValueError) as cm:
            api1 = Obfuscator(  # noqa: F841
                obfuscation_key=obfuscation_key,
                obfuscation_secret=obfuscation_secret,
            )

        self.assertEqual(
            cm.exception.args[0],
            "Submit one and only one of: `obfuscation_key` or `obfuscation_secret`.",
        )

        api2 = Obfuscator(
            obfuscation_key=obfuscation_key,
        )
        self.assertIsInstance(api2, Obfuscator)

        api3 = Obfuscator(
            obfuscation_secret=obfuscation_secret,
        )
        self.assertIsInstance(api3, Obfuscator)

    def test_roundtrip_key(self):
        api2 = Obfuscator(
            obfuscation_key=obfuscation_key,
        )
        obfuscated = api2.obfuscate(data_string)
        self.assertEqual(obfuscated, data_string_obfuscated["obfuscation_key"])
        deobfuscated = api2.obfuscate(obfuscated)
        self.assertEqual(deobfuscated, data_string)

    def test_roundtrip_secret(self):
        api3 = Obfuscator(
            obfuscation_secret=obfuscation_secret,
        )
        obfuscated = api3.obfuscate(data_string)
        self.assertEqual(obfuscated, data_string_obfuscated["obfuscation_secret"])
        deobfuscated = api3.obfuscate(obfuscated)
        self.assertEqual(deobfuscated, data_string)


class Test_SecureEnough(unittest.TestCase):
    def test_create(self):
        # can we make an Obfuscator correctly?

        with self.assertRaises(ValueError) as cm:
            api1 = SecureEnough(  # noqa: 841
                use_obfuscation=True,
                obfuscation_key=obfuscation_key,
                obfuscation_secret=obfuscation_secret,
            )

        self.assertEqual(
            cm.exception.args[0],
            "Must submit only one of: `obfuscation_secret`, `obfuscation_key`.",
        )

        api2 = SecureEnough(
            use_obfuscation=True,
            obfuscation_key=obfuscation_key,
        )
        self.assertIsInstance(api2, SecureEnough)

        api3 = SecureEnough(
            use_obfuscation=True,
            obfuscation_secret=obfuscation_secret,
        )
        self.assertIsInstance(api3, SecureEnough)

    def test_roundtrip_key(self):
        api2 = SecureEnough(
            app_secret=app_secret__bytes,
            use_obfuscation=True,
            obfuscation_key=obfuscation_key,
        )
        obfuscated = api2.encode(data_string, hashtime=False)
        self.assertEqual(obfuscated, data_string_encoded["obfuscation_key"])

    def test_roundtrip_secret(self):
        api3 = SecureEnough(
            app_secret=app_secret__bytes,
            use_obfuscation=True,
            obfuscation_secret=obfuscation_secret,
        )
        obfuscated = api3.encode(data_string, hashtime=False)
        self.assertEqual(obfuscated, data_string_encoded["obfuscation_secret"])
