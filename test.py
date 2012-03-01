import secure_enough
from secure_enough import SecureEnough

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

factory= SecureEnough(app_secret='517353cr37' , use_rsa_encryption=False , rsa_key_private=rsa_key_private , rsa_key_private_passphrase=rsa_key_private_passphrase )

if 0 :
	
	print ""    
	print "Test - SecureEnough.encrypt"
	print factory.encrypt( 'hello' )
	print factory.encode_payload( {'hello':'howareyou'} )
	print factory.encode_payload( ['hello','howareyou'] )
	

if 1 :
	#serialized=  factory.encode_payload( {'hello':'howareyou'} )
	#deserialized=  factory.decode_payload( serialized )
	encrypted=  factory.encrypt( {'hello':'howareyou'} , hashtime=True )
	decrypted=  factory.decrypt( encrypted , hashtime=True )

	#print "serialized - %s" % serialized
	#print "deserialized - %s" % deserialized
	print "encrypted - %s" % encrypted
	print "decrypted - %s" % decrypted


if 0 :
	print ""    
	print "Test - SecureEnough.obfuscate"
	obs= SecureEnough.obfuscate( 'hello' )
	obs2= SecureEnough.obfuscate(obs)
	print obs
	print obs2
	print ""    
	print ""
	
	
	
	
	
if 0 :
	
	print "SecureEnough.base64_url_encode"  
	encoded= SecureEnough.base64_url_encode( 'Aa=as' )
	print encoded
	print ""    
	print ""    
	
	print "SecureEnough.base64_url_decode"  
	decoded= SecureEnough.base64_url_decode( encoded )
	print decoded
	print ""    
	print ""    
	
	
	print "data"    
	data= { 'user.id':1 , 'name':'jonathan' }
	print data
	print ""    
	print ""    
	
	print "SecureEnough.signed_request_create"  
	signed= SecureEnough.signed_request_create( data , secret='123' )
	print signed
	print ""    
	print ""    
	
	print "SecureEnough.signed_request_verify"  
	unsigned= SecureEnough.signed_request_verify( signed , secret='123' )
	print unsigned
	print ""    
	print ""    
	
