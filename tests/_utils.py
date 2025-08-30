from typing import Dict
from typing import Optional

from insecure_but_secure_enough import ConfigurationProvider

# ==============================================================================

aes_secret = b"insecure_but_secure_enough"

app_secret__bytes = b"517353cr37"
app_secret__string = app_secret__bytes.decode()

app_secret_wrong__bytes = b"not-the-app-secret"
app_secret_wrong__string = app_secret_wrong__bytes.decode()

data: Dict[str, str] = {"hello": "world!"}

data_string = "abcdefg"
data_string_obfuscated: Dict[str, str] = {
    "obfuscation_key": "\x0e\x00\x05\x11\x16\x05\x06",
    "obfuscation_secret": "R\x03R\\\x00Q\x04",
}
data_string_encoded: Dict[str, str] = {
    "obfuscation_key": "DgAFERYFBg",
    "obfuscation_secret": "UgNSXABRBA",
}

obfuscation_key = "obfuscation_key"
obfuscation_secret = b"obfuscation_secret"

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


class _Testing_ConfigurationProvider(ConfigurationProvider):
    """testing for configuration provider"""

    def app_secret(
        self,
        timestamp: Optional[int] = None,
    ) -> bytes:
        return app_secret__bytes


ConfigurationProvider_app_secret = _Testing_ConfigurationProvider()
