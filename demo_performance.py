from __future__ import print_function

import hashlib
import os
import random
import timeit

from insecure_but_secure_enough import SecureEnough


def randomhash(length=8):
    if length > 40:
        raise ValueError("randomhash - length must be <= 40")
    if length < 0:
        raise ValueError("randomhash - length must be > 0")
    return hashlib.sha1(os.urandom(60)).hexdigest()[0:length]


# init values

# #
# #  our payload should be something that might hold 10 fields of ids
# #
def generate_payload():
    payload = {}
    for i in range(1, 10):
        k = randomhash(length=random.randint(4, 15))
        v = random.randint(10000, 1000000000)
        payload[k] = v
    return payload


# # the following payload was generated with the above function
payload = {
    "3b837ba7facceaa": 110466813,
    "ad255d1ad80c9": 63879546,
    "f85711697": 576164405,
    "0fd602335": 606091169,
    "8be808c9f636e09": 380277405,
    "d12b0": 372015325,
    "031a2583a5812b": 893746556,
    "5e7587d8": 32400442,
    "9e5ebd40596c84": 645607501,
}

global_app_secret = "d2IYlyCMdJDDGu4C9WHC1wTbdaqogGWcdpmZk17og3j2e7tQ4JTX0nhMTHHPKvPx"

# ## generated via `openssl genrsa -des3 -out private.pem 1024`
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

factories = {}
factories["ise-rsa"] = SecureEnough(
    app_secret=global_app_secret,
    use_rsa_encryption=True,
    rsa_key_private=rsa_key_private,
    rsa_key_private_passphrase=rsa_key_private_passphrase,
)
factories["ise-aes"] = SecureEnough(
    app_secret=global_app_secret,
    use_aes_encryption=True,
    aes_secret=global_app_secret,
)
factories["ise-signing"] = SecureEnough(
    app_secret=global_app_secret, use_rsa_encryption=False, use_obfuscation=False
)


# ##
# ## store some values for decryption tests
computed = {}
computed["ise-rsa"] = factories["ise-rsa"].encode(payload, hashtime=False)
computed["ise-aes"] = factories["ise-aes"].encode(payload, hashtime=False)
computed["ise-signing:serialized_plaintext_encode"] = factories[
    "ise-signing"
].serialized_plaintext_encode(payload)
computed["ise-signing:hmac_sha1_encode"] = factories["ise-signing"].hmac_sha1_encode(
    payload
)
computed["ise-signing:hmac_sha256_encode"] = factories[
    "ise-signing"
].hmac_sha256_encode(payload)
computed["ise-signing:signed_request"] = SecureEnough.signed_request_create(
    payload, secret=global_app_secret
)

# ## store the tests
tests = {}


# ##
# ## the test routines


# #
# #  ise - RSA
# #


def ise_rsa_encrypt():
    signed = factories["ise-rsa"].encode(payload, hashtime=False)


tests["ise_rsa_encrypt"] = ise_rsa_encrypt


def ise_rsa_decrypt():
    valid = factories["ise-rsa"].decode(computed["ise-rsa"], hashtime=False)


tests["ise_rsa_decrypt"] = ise_rsa_decrypt


def ise_rsa_roundtrip():
    try:
        signed = factories["ise-rsa"].encode(payload, hashtime=False)
        valid = factories["ise-rsa"].decode(signed, hashtime=False)
    except Exception as e:
        raise


tests["ise_rsa_roundtrip"] = ise_rsa_roundtrip


# #
# #  ise - AES
# #


def ise_aes_encrypt():
    signed = factories["ise-aes"].encode(payload, hashtime=False)


tests["ise_aes_encrypt"] = ise_aes_encrypt


def ise_aes_decrypt():
    valid = factories["ise-aes"].decode(computed["ise-aes"], hashtime=False)


tests["ise_aes_decrypt"] = ise_aes_decrypt


def ise_aes_roundtrip():
    signed = factories["ise-aes"].encode(payload, hashtime=False)
    valid = factories["ise-aes"].decode(signed, hashtime=False)


tests["ise_aes_roundtrip"] = ise_aes_roundtrip


# #
# #  ise - serialized_plaintext
# #


def ise_serialized_plaintext_encode():
    signed = factories["ise-signing"].serialized_plaintext_encode(payload)


tests["ise_serialized_plaintext_encode"] = ise_serialized_plaintext_encode


def ise_serialized_plaintext_decode():
    valid = factories["ise-signing"].serialized_plaintext_decode(
        computed["ise-signing:serialized_plaintext_encode"]
    )


tests["ise_serialized_plaintext_decode"] = ise_serialized_plaintext_decode


def ise_serialized_plaintext_roundtrip():
    signed = factories["ise-signing"].serialized_plaintext_encode(payload)
    valid = factories["ise-signing"].serialized_plaintext_decode(signed)


tests["ise_serialized_plaintext_roundtrip"] = ise_serialized_plaintext_roundtrip


# #
# #  ise - hmac_sha1
# #


def ise_hmac_sha1_encode():
    signed = factories["ise-signing"].hmac_sha1_encode(payload)


tests["ise_hmac_sha1_encode"] = ise_hmac_sha1_encode


def ise_hmac_sha1_decode():
    valid = factories["ise-signing"].hmac_sha1_decode(
        computed["ise-signing:hmac_sha1_encode"]
    )


tests["ise_hmac_sha1_decode"] = ise_hmac_sha1_decode


def ise_hmac_sha1_roundtrip():
    signed = factories["ise-signing"].hmac_sha1_encode(payload)
    valid = factories["ise-signing"].hmac_sha1_decode(signed)


tests["ise_hmac_sha1_roundtrip"] = ise_hmac_sha1_roundtrip


# #
# #  ise - hmac_sha256
# #
def ise_hmac_sha256_encode():
    signed = factories["ise-signing"].hmac_sha256_encode(payload)


tests["ise_hmac_sha256_encode"] = ise_hmac_sha256_encode


def ise_hmac_sha256_decode():
    valid = factories["ise-signing"].hmac_sha256_decode(
        computed["ise-signing:hmac_sha256_encode"]
    )


tests["ise_hmac_sha256_decode"] = ise_hmac_sha256_decode


def ise_hmac_sha256_roundtrip():
    signed = factories["ise-signing"].hmac_sha256_encode(payload)
    valid = factories["ise-signing"].hmac_sha256_decode(signed)


tests["ise_hmac_sha256_roundtrip"] = ise_hmac_sha256_roundtrip


# #
# #  ise - signed_request
# #
def ise_signed_request_encode():
    signed = SecureEnough.signed_request_create(payload, secret=global_app_secret)


tests["ise_signed_request_encode"] = ise_signed_request_encode


def ise_signed_request_decode():
    valid = SecureEnough.signed_request_verify(
        computed["ise-signing:signed_request"], secret=global_app_secret
    )


tests["ise_signed_request_decode"] = ise_signed_request_decode


def ise_signed_request_roundtrip():
    signed = SecureEnough.signed_request_create(payload, secret=global_app_secret)
    valid = SecureEnough.signed_request_verify(signed, secret=global_app_secret)


tests["ise_signed_request_roundtrip"] = ise_signed_request_roundtrip


# ##
# ## Run the tests
# ##

# ## ise_rsa
n = 100
statements = [
    """tests['ise_rsa_encrypt']()""",
    """tests['ise_rsa_decrypt']()""",
    """tests['ise_rsa_roundtrip']()""",
    """tests['ise_aes_encrypt']()""",
    """tests['ise_aes_decrypt']()""",
    """tests['ise_aes_roundtrip']()""",
    """tests['ise_serialized_plaintext_encode']()""",
    """tests['ise_serialized_plaintext_decode']()""",
    """tests['ise_serialized_plaintext_roundtrip']()""",
    """tests['ise_hmac_sha1_encode']()""",
    """tests['ise_hmac_sha1_decode']()""",
    """tests['ise_hmac_sha1_roundtrip']()""",
    """tests['ise_hmac_sha256_encode']()""",
    """tests['ise_hmac_sha256_decode']()""",
    """tests['ise_hmac_sha256_roundtrip']()""",
    """tests['ise_signed_request_encode']()""",
    """tests['ise_signed_request_decode']()""",
    """tests['ise_signed_request_roundtrip']()""",
]
for s in statements:
    t = timeit.Timer(
        stmt=s, setup="from __main__ import payload, factories, computed, tests "
    )
    print("%s || %s || %s" % (n, t.timeit(n), s))
