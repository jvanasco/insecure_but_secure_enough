# stdlib
import datetime
from time import time
from typing import Optional
import unittest

# local
import insecure_but_secure_enough
from insecure_but_secure_enough import Obfuscator
from insecure_but_secure_enough import SecureEnough


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


aes_secret = "insecure_but_secure_enough"

data = {"hello": "world!"}
app_secret = "517353cr37"
app_secret_wrong = "not-the-app-secret"
data_string = "abcdefg"
data_string_obfuscated = {
    "obfuscation_key": "TSTWPU\x04",
    "obfuscation_secret": "P\x06\x01T\x01\x05_",
}
data_string_encoded = {
    "obfuscation_key": "VFNUV1BVBA",
    "obfuscation_secret": "UAYBVAEFXw",
}


class Test_Obfuscator(unittest.TestCase):
    def test_create(self):
        # can we make an Obfuscator correctly?

        with self.assertRaises(ValueError) as cm:
            api1 = Obfuscator(
                obfuscation_key=app_secret,
                obfuscation_secret=app_secret,
            )

        self.assertEqual(
            cm.exception.args[0],
            "Submit one and only one of: `obfuscation_key` or `obfuscation_secret`.",
        )

        api2 = Obfuscator(
            obfuscation_key=app_secret,
        )

        api3 = Obfuscator(
            obfuscation_secret=app_secret,
        )

    def test_rountrip_key(self):
        api2 = Obfuscator(
            obfuscation_key=app_secret,
        )
        obfuscated = api2.obfuscate(data_string)
        self.assertEqual(obfuscated, data_string_obfuscated["obfuscation_key"])
        deobfuscated = api2.obfuscate(obfuscated)
        self.assertEqual(deobfuscated, data_string)

    def test_rountrip_secret(self):
        api3 = Obfuscator(
            obfuscation_secret=app_secret,
        )
        obfuscated = api3.obfuscate(data_string)
        self.assertEqual(obfuscated, data_string_obfuscated["obfuscation_secret"])
        deobfuscated = api3.obfuscate(obfuscated)
        self.assertEqual(deobfuscated, data_string)


class Test_SecureEnough(unittest.TestCase):
    def test_create(self):
        # can we make an Obfuscator correctly?

        with self.assertRaises(ValueError) as cm:
            api1 = SecureEnough(
                use_obfuscation=True,
                obfuscation_key=app_secret,
                obfuscation_secret=app_secret,
            )

        self.assertEqual(
            cm.exception.args[0],
            "Must submit only one of: `obfuscation_secret`, `obfuscation_key`.",
        )

        api2 = SecureEnough(
            use_obfuscation=True,
            obfuscation_key=app_secret,
        )

        api3 = SecureEnough(
            use_obfuscation=True,
            obfuscation_secret=app_secret,
        )

    def test_rountrip_key(self):
        api2 = SecureEnough(
            app_secret=app_secret,
            use_obfuscation=True,
            obfuscation_key=app_secret,
        )
        obfuscated = api2.encode(data_string, hashtime=False)
        self.assertEqual(obfuscated, data_string_encoded["obfuscation_key"])

    def test_rountrip_secret(self):
        api3 = SecureEnough(
            app_secret=app_secret,
            use_obfuscation=True,
            obfuscation_secret=app_secret,
        )
        obfuscated = api3.encode(data_string, hashtime=False)
        self.assertEqual(obfuscated, data_string_encoded["obfuscation_secret"])
