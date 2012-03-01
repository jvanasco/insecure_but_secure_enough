"""

This package is insecure, but secure enough.

The idea for secure_enough to allow for "autologin cookies" and "instant login" urls for stupid social web applications.

Two important things to note:

    1. You should not use this module for financial transactions or sensitive info.  That would be egregiously stupid.
    2. If you log someone in with this , you should note the login as "insecure" and require them to provide a password to view sensitive data or any 'write' activity. 
    

Long ago, I had a class that would do a trivial encryption on cookie data, coupled with a lightweight hash to handle timeout events.  This way you wouldn't always have to decrypt data to do a light verification.  The general flow was this:

To encode:
    cookie = encypted_data + timestamp + hash(encrypted_data + timestamp + secret )
    
To decode:
    ( payload , timestamp , hash ) = cookie
    if hash != hash ( payload , timestamp , secret ):
        raise InvalidHash()
    if timestamp > timeout:
        raise Timeout()
    data = decrypt(payload)

The encryption I used was a lightweight port from a CPAN module, so it could be blown away in seconds today.

When i decided to re-implement this, looking around I found a handful of similar projects - which I've borrowed heavily from.

They include:
    https://github.com/dziegler/django-urlcrypt/blob/master/urlcrypt/lib.py
    http://docs.pylonsproject.org/projects/pyramid/en/1.3-branch/api/session.html#pyramid.session.signed_serialize
    https://developers.facebook.com/docs/authentication/signed_request/

This largely re-implements all of those, along with some other functionality.

Right now, data is a base64_url_encoded version of a string, concatenated list, or json object (for dicts).  I opted against using pickle, because this format makes it easier to work with other web technologies ( js, php, etc ).  this might move to an all json version shortly.

Check test.py to see an overview of how this works.


# Signed Requests

signed_request_create
and
signed_request_verify

are both handled as @classmethods - along with their support functions.  that means you can call them directly without an object instance.

I built them as @classmethods instead of package functions... because if you want to extend the options for digest mods, you can just subclass SecureEnough and overwrite _digestmod to add more providers.

# Encrypting and Signing Cookies

Encrypting cookies currently happens via a 'global' RSA key for an instance of SecureEnough().  [ you provide details for it in the __init__() ]

Similarly, there are 

If you so desire, you can use timestamped based app_secrets, obfuscators and rsa keys.

The flow is as such:

1. Subclass the ConfigurationProvider() and overwrite the relevant hooks.  The requesting mehtods pass a single argument - timestamp - which should give you enough to go on.  Note that app_secret returns a string, while the obfuscator must return an object that can `obfuscate` and `deobfuscate` ; and rsa_key requires an object that can `encrypt` and `decrypt`.  This libray provides default functionality through wrapper objects you can mimic.

2. Instantiate a SecureEnough() object, and register the relevant providers

3. When encrypting data, SecureEnough() will ask the ConfigurationProvider() for the approprite keys/secrets for the current time() .  When decrypting data, SecureEnough() will ask the ConfigurationProvider() for the approprite keys/secrets for the time in the cookie/hash (if there is one) .  

This flow will allow you to easily create a plethora of site secrets and RSA keys -- as in a new one each day -- which means that while this module is not actually secure, it is Secure Enough for most web applications.

"""


import base64
import hashlib
import hmac
from time import time
import simplejson as json
from Crypto.PublicKey import RSA 
import types
import os

from oaep import OAEP



class Invalid(Exception):
    pass

class InvalidChecksum(Invalid):
    pass

class InvalidPayload(Invalid):
    pass

class InvalidTimeout(Invalid):
    pass

class InvalidSecret(Invalid):
    """Raised when a secret it too old"""
    pass



        
class RsaKeyHolder(object):
    """wraps an RSA key"""
    key= None
    _key_private= None
    _key_private_passphrase= None
    key_length_bytes= None
    block_bytes= None
    padder= None
    
    def __init__( self , key_private=None , key_private_passphrase=None ):
        self._key_private = key_private
        self._key_private_passphrase = key_private_passphrase
        if self._key_private_passphrase:
            self.key= RSA.importKey( self._key_private , self._key_private_passphrase )
        else:
            self.key= RSA.importKey( self._key_private )
        self.key_length_bytes= int((self.key.size() + 1) / 8)
        self.block_bytes=  self.key_length_bytes - 2 * 20 - 2 # from oaep.py
        self.padder= OAEP(os.urandom)

        
    def encrypt(self,s):
        encrypted_blocks = []
        for block in self.split_string(s, self.block_bytes):
            padded_block = self.padder.encode(self.key_length_bytes, block) # will raise ValueError if token is too long
            encrypted_block = self.key.encrypt(padded_block, None)[0]
            encrypted_blocks.append(encrypted_block)
        return ''.join(encrypted_blocks)
        
    def decrypt(self,s):
        decrypted_blocks = []
        for block in self.split_string(s, self.key_length_bytes):
            padded_block = '\x00' + self.key.decrypt(block) # NUL byte is apparently dropped by decryption
            decrypted_block = self.padder.decode(self.key_length_bytes, padded_block) # will raise ValueError on corrupt token
            decrypted_blocks.append(decrypted_block)
        return ''.join(decrypted_blocks)

    def split_string(self,s, block_size):
        blocks = []
        start = 0
        while start < len(s):
            block = s[start:start+block_size]
            blocks.append(block)
            start += block_size
        return blocks




class Obfuscator(object):
    obfuscation_key= None
    obfuscation_secret= None
    
    def __init__( self , obfuscation_key , obfuscation_secret ):
        self.obfuscation_key= obfuscation_key
        self.obfuscation_secret= obfuscation_secret
        self.obfuscation_secret= obfuscation_secret
        self.obfuscation_key = obfuscation_key
        if not obfuscation_key:
            self.obfuscation_key = hashlib.sha512(obfuscation_secret).digest() + hashlib.sha512(obfuscation_secret[::-1]).digest()

    def obfuscate( self , text ):
        # copy out our OBFUSCATE_KEY to the length of the text
        key = self.obfuscation_key * (len(text)//len(self.obfuscation_key) + 1)
        # XOR each character from our input with the corresponding character from the key
        xor_gen = (chr(ord(t) ^ ord(k)) for t, k in zip(text, key))
        return ''.join(xor_gen)
        
    deobfuscate = obfuscate
    



class ConfigurationProvider(object):
    """Create and build configuration providers"""

    def app_secret(timestamp):
        """for a given timestamp, this should return the appropriate app secret"""
        return ''

    def obfuscator(timestamp):
        """for a given timestamp, this should return the appropriate obfuscator"""
        obfuscation_secret= ''
        obfuscation_key= ''
        return Obfuscator( obfuscation_key , obfuscation_secret )

    def rsa_key(timestamp):
        """for a given timestamp, this should return the appropriate RSA Key"""
        rsa_key_private= ''
        rsa_key_private_passphrase= ''
        return RsaKeyHolder( key_private = rsa_key_private , key_private_passphrase = rsa_key_private_passphrase )



class SecureEnough(object):
    config_app_secret= None
    config_obfuscation= None
    config_rsa= None

    use_rsa_encryption = False
    use_obfuscation= False

    _app_secret= None

    def __init__( self ,
            config_app_secret=None ,
            app_secret='' , 

            use_rsa_encryption=False , 
            config_rsa= None,
            rsa_key_private=None , 
            rsa_key_private_passphrase=None , 

            use_obfuscation=False ,
            config_obfuscation=None,
            obfuscation_secret='' , 
            obfuscation_key= None
        ):
        if config_app_secret:
            config_app_secret= config_app_secret
        else:
            self._app_secret= app_secret

        if use_rsa_encryption:
            self.use_rsa_encryption= use_rsa_encryption
            if config_rsa:
                self.config_rsa= config_rsa
            else:
                self._rsa_key= RsaKeyHolder( key_private = rsa_key_private , key_private_passphrase = rsa_key_private_passphrase )

        if use_obfuscation:
            self.use_obfuscation= use_obfuscation
            if config_obfuscation: 
                self.config_obfuscation= config_obfuscation
            else:
                self._obfuscator= Obfuscator( obfuscation_key , obfuscation_secret)
                


    def obfuscator( self , timestamp=None ):
        print "requesting obfuscator for %s" % timestamp
        if self.config_obfuscation :
            return self.config_obfuscation.obfuscator(timestamp)
        return self._obfuscator

    def rsa_key( self , timestamp=None ):
        print "requesting rsa_key for %s" % timestamp
        if self.config_rsa :
            return self.config_rsa.rsa_key(timestamp)
        return self._rsa_key
    
    def app_secret( self , timestamp=None ):
        print "requesting app_secret for %s" % timestamp
        if self.config_app_secret :
            return self.config_app_secret.app_secret(timestamp)
        return self._app_secret
    

    @classmethod
    def _base64_url_encode(cls,text):
        """this is just wrapping base64.urlsafe_b64encode , to allow for a later switch"""
        padded_b64 = base64.urlsafe_b64encode(text)
        return padded_b64.replace('=', '') # = is a reserved char

    @classmethod
    def _base64_url_decode(cls,inp):
        """this is essentially wrapping base64.base64_url_decode , to allow for a later switch"""
        padding_factor = (4 - len(inp) % 4) % 4
        inp += "=" * padding_factor 
        return base64.urlsafe_b64decode(inp)
        
    @classmethod
    def _digestmod(cls, algorithm=None):
        if algorithm == 'HMAC-SHA256':
            digestmod= hashlib.sha256
        elif algorithm == 'HMAC-SHA1':
            digestmod= hashlib.sha1
        else:
            raise ValueError("unsupported algorithm")
        return digestmod

    @classmethod
    def signed_request_create( cls , data , secret=None , timeout=None , algorithm="HMAC-SHA256" ):
        digestmod= cls._digestmod(algorithm)
        data['algorithm'] = algorithm
        payload= cls._base64_url_encode( json.dumps(data) )
        signature= hmac.new( secret , msg=payload , digestmod=digestmod ).hexdigest()
        return signature + '.' + payload


    @classmethod
    def signed_request_verify( cls , signed_request=None , secret=None , timeout=None , algorithm="HMAC-SHA256" ):
        """This is compatible with signed requests from facebook.com (https://developers.facebook.com/docs/authentication/signed_request/) 
        
        returns a tuple of (Boolean,Dict), where Dict is the Payload and Boolean is True/False based on an optional timeout.  Raises an "Invalid" if a serious error occurs. """
        digestmod= cls._digestmod(algorithm)

        (signature,payload)= signed_request.split('.')

        decoded_signature = cls._base64_url_decode(signature)
        payload_decoded= cls._base64_url_decode(payload)
        data = json.loads(payload_decoded)

        if data.get('algorithm').upper() != algorithm:
            raise Invalid('unexpected algorithm.  Wanted %s , Received %s' % (algorithm,data.get('algorithm')) )

        expected_sig = hmac.new( secret , msg=payload , digestmod=digestmod ).hexdigest()
    
        if signature != expected_sig:
            raise Invalid('invalid signature.  signature (%s) != expected_sig (%s)' % ( signature , expected_sig ) )
            
        if timeout:
            time_now= int(time())
            diff = time_now - data['issued_at']
            if ( diff > timeout ) :
                return ( False , data )

        return ( True , data )        


    def _serialize( self , data ):
        serialized= None
        if isinstance( data , types.DictType ):
            serialized= json.dumps(data)
        elif isinstance( data , types.ListType ) or isinstance( data , types.TupleType ) : 
            assert '|' not in ''.join(data)
            serialized= '|'.join(data)
        elif isinstance( data , types.StringTypes ):
            assert '|' not in data
            serialized= data
        else:
            raise TypeError('invalid type for serialization')
        return serialized



    def _deserialize( self , serialized ):
        data = None
        try :
            data= json.loads( serialized )
        except json.decoder.JSONDecodeError :
            if '|' in serialized :
                data= serialized.split('|')
            else:
                data= serialized
        return data



    def _hmac_for_timestamp( self , payload , timestamp , algorithm="HMAC-SHA1" ):
        digestmod= self._digestmod(algorithm)
        message= "%s||%s" % ( payload , timestamp ) 
        app_secret= self.app_secret( timestamp=timestamp )
        return hmac.new( app_secret , msg=message , digestmod=digestmod ).hexdigest()



    def encode( self , data , hashtime=True , hmac_algorithm="HMAC-SHA1"):
        """encode data"""
        # compute the time, which is used for verification and coordinating the right secrets
        time_now= None
        if hashtime:
            time_now= int(time())
        
        # encode the payload , which serializes it and possibly obfuscates it
        
        # .. first we serialize it
        payload = self._serialize( data )

        # .. optionally include lightweight obfuscation
        if self.use_obfuscation:
            payload=  self.obfuscator(timestamp=time_now).obfuscate( payload )

		# .. optionally encrypt the payload
        if self.use_rsa_encryption:
            payload = self.rsa_key( timestamp=time_now ).encrypt( payload )

        # finally urlencode it
        payload= self._base64_url_encode( payload )

        # if we're computing time-sensitive keys or expiration, we'll return a compound token
        if hashtime:
            hash= self._hmac_for_timestamp( payload , time_now , algorithm=hmac_algorithm )
            compound= "%s|%s|%s" % ( payload , time_now , hash )
            return compound
        # otherwise, just return the payload
        return payload



    def decode( self, payload , hashtime=True , timeout=None , hmac_algorithm="HMAC-SHA1"):
        """decode data"""
        
        # if we dont have hashtime support, this needs to be None...
        time_then= None

        # try to validate the hashtime
        if hashtime :
            ( payload , time_then , hash_received )= payload.split('|')
            hash_expected= self._hmac_for_timestamp( payload , time_then , algorithm=hmac_algorithm )
            if hash_expected != hash_received:
                raise InvalidChecksum()
            if timeout:
                time_now= int(time())
                if ( (time_now - time_then) > timeout ) :
                    raise InvalidTimeout()

        # decoding is done in reverse of encoding
		# so decrypt, then deobfuscate

        payload = self._base64_url_decode(payload)
        
        if self.use_rsa_encryption:
            payload = self.rsa_key( timestamp=time_then ).decrypt(payload)

        if self.use_obfuscation :
            payload=  self.obfuscator(timestamp=time_then).deobfuscate( payload )

        payload = self._deserialize(payload)

        return payload


