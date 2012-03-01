import secure_enough
from secure_enough import SecureEnough


### generated via `openssl genrsa -des3 -out private.pem 1024`
rsa_key_private= """-----BEGIN RSA PRIVATE KEY-----
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
rsa_key_private_passphrase= """tweet"""
rsa_key_public= None

data= {'hello':'howareyou'}


## create a factory
encryptionFactory= SecureEnough(\
        app_secret = '517353cr37' , 
        use_rsa_encryption = True , 
        rsa_key_private = rsa_key_private , 
        rsa_key_private_passphrase = rsa_key_private_passphrase 
    )

encrypted=  encryptionFactory.encode( data , hashtime=True )
decrypted=  encryptionFactory.decode( encrypted , hashtime=True )

print "Illustrating Encryption..."
print "	data - %s" % data
print "	encrypted - %s" % encrypted
print "	decrypted - %s" % decrypted


## create a factory
signingFactory= SecureEnough(\
        app_secret = '517353cr37' , 
        use_rsa_encryption = False , 
        use_obfuscation = False 
    )

signed=  signingFactory.encode( data , hashtime=True )
signed_validated=  signingFactory.decode( signed , hashtime=True )
unsigned=  signingFactory.encode( data , hashtime=False )
unsigned_validated=  signingFactory.decode( unsigned , hashtime=False )

print "Illustrating Signing..."
print "	data - %s" % data
print "	signed (timebased+sha1) - %s" % signed
print "	validated (timebased+sha1) - %s" % signed_validated
print "	unsigned - %s" % unsigned
print "	unsigned validated - %s" % unsigned_validated


signed=  signingFactory.encode( data , hashtime=True , hmac_algorithm="HMAC-SHA256" )
signed_validated=  signingFactory.decode( signed , hashtime=True , hmac_algorithm="HMAC-SHA256" )
print "	data - %s" % data
print "	signed (timebased+sha256) - %s" % signed
print "	validated (timebased+sha256) - %s" % signed_validated



print "Illustrating Signed Requests..."
print "SecureEnough.signed_request_create"  
signed= SecureEnough.signed_request_create( data , secret='123' )
print signed
print "SecureEnough.signed_request_verify"  
verified= SecureEnough.signed_request_verify( signed , secret='123' )
print verified

