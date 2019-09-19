from __future__ import print_function

from insecure_but_secure_enough import SecureEnough


# generated via `openssl genrsa -des3 -out private.pem 1024`
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

data = {"hello": "howareyou"}


# create a factory for encryption
encryptionFactory = SecureEnough(
    app_secret="517353cr37",
    use_rsa_encryption=True,
    rsa_key_private=rsa_key_private,
    rsa_key_private_passphrase=rsa_key_private_passphrase,
)

encryptionFactoryAES = SecureEnough(
    app_secret="517353cr37", use_aes_encryption=True, aes_secret="123124"
)


# create a factory for signing
signingFactory = SecureEnough(
    app_secret="517353cr37", use_rsa_encryption=False, use_obfuscation=False
)


print("")
print("**********************************************************************")
print("")

print("Illustrating Encryption...")
print("""Encryption is the most secure option. """)
print("-----------------------------------")
print("""Let's use an RSA key to encrypt the payload.  """)

encrypted = encryptionFactory.encode(data, hashtime=True)
decrypted = encryptionFactory.decode(encrypted, hashtime=True)
print("    data - %s" % data)
print("    encrypted (rsa) - %s" % encrypted)
print("    decrypted (rsa) - %s" % decrypted)
print("-----------------------------------")
print("""Let's use an AES cipher to encrypt the payload.  """)

encrypted = encryptionFactoryAES.encode(data)
decrypted = encryptionFactoryAES.decode(encrypted)
print("    data - %s" % data)
print("    encrypted (aes)- %s" % encrypted)
print("    decrypted (aes)- %s" % decrypted)

print("")
print("**********************************************************************")
print("")


print("Illustrating Signing Data...")
print(
    """Signing data doesn't encrypt anything. It merely creates a signature to verify the payload."""
)
print("-----------------------------------")
print("""Raw Data.""")
print(
    """The simplest.  No signature.  Just raw data that is encoded & serialized for transport."""
)

raw_data = signingFactory.encode(data, hashtime=False)
raw_data_validated = signingFactory.decode(raw_data, hashtime=False)
print("    data - %s" % data)
print("    raw_data () - %s" % raw_data)
print("    validated () - %s" % raw_data_validated)
print("-----------------------------------")
print("""HMAC signature (SHA1)""")
print(
    """Creates a payload that looks like (serialized_data|timestamp|digest).  digest is built off serialized_data+timestamp+app_secret """
)

signed_sha1 = signingFactory.encode(data, hashtime=True)
signed_sha1_validated = signingFactory.decode(signed_sha1, hashtime=True)
print("    data - %s" % data)
print("	   payload  - %s" % signed_sha1)
print("	   validated - %s" % signed_sha1_validated)
print("-----------------------------------")
print("""HMAC signature (SHA256)""")
print(
    """Creates a payload that looks like (serialized_data|timestamp|digest).  digest is built off serialized_data+timestamp+app_secret """
)

signed_sha256 = signingFactory.encode(data, hashtime=True, hmac_algorithm="HMAC-SHA256")
signed_sha256_validated = signingFactory.decode(
    signed_sha256, hashtime=True, hmac_algorithm="HMAC-SHA256"
)
print("    data - %s" % data)
print("    payload - %s" % signed_sha256)
print("    validated - %s" % signed_sha256_validated)
print("")

print("**********************************************************************")
print("")
print("")
print("Illustrating Signed Requests...")
print(
    "This is another implementation of HMAC-256, but in a format that is compatible with Facebook and some other sites"
)
print("Note this is a classmethod, not an object method")
print(
    "Note that we return a tuple (valid, payload) AND the payload contains the algorithm"
)

request_signed = SecureEnough.signed_request_create(data, secret="123")
request_verified = SecureEnough.signed_request_verify(request_signed, secret="123")
print("    data - %s" % data)
print("    payload | %s" % request_signed)
print("    validated | %s" % str(request_verified))
print("")
print("")

print("**********************************************************************")
print("")
print("Illustrating Shortcuts...")
print("----")

serialized_plaintext_encode = signingFactory.serialized_plaintext_encode(data)
serialized_plaintext_decode = signingFactory.serialized_plaintext_decode(
    serialized_plaintext_encode
)
print("")
print("serialized_plaintext_encode = %s" % serialized_plaintext_encode)
print("serialized_plaintext_decode = %s" % serialized_plaintext_decode)
print("")

hmac_sha1_encode = signingFactory.hmac_sha1_encode(data)
hmac_sha1_decode = signingFactory.hmac_sha1_decode(hmac_sha1_encode)
print("")
print("hmac_sha1_encode = %s" % hmac_sha1_encode)
print("hmac_sha1_decode = %s" % hmac_sha1_decode)
print("")

hmac_sha256_encode = signingFactory.hmac_sha256_encode(data)
hmac_sha256_decode = signingFactory.hmac_sha256_decode(hmac_sha256_encode)
print("")
print("hmac_sha256_encode = %s" % hmac_sha256_encode)
print("hmac_sha256_decode = %s" % hmac_sha256_decode)
print("")
