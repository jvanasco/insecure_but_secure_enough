"""

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

# Signed Requests

signed_request_create
and
signed_request_verify

are both handled as @classmethods - along with their support functions.  that means you can call them directly without an object instance.

I built them as @classmethods instead of package functions... because if you want to extend the options for digest mods, you can just subclass SecureEnough and overwrite _digestmod to add more providers.

# Encrypting Cookies

Encrypting cookies currently happens via a 'global' RSA key for an instance of SecureEnough().  [ you provide it on the init() ]

My goal is to extend the class to use a timetstamped lookup function, via the ConfigurationProvider()

The flow will likely be this:

1. Subclass ConfigurationProvider() and overwrite the hooks you want.
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


class ConfigurationProvider(object):
    """Create and build configuration providers"""

    def app_secret(timestamp):
        return ''

    def obfuscation(timestamp):
        obfuscation_secret= ''
        obfuscation_key= ''
        return obfuscation_secret , obfuscation_key

    def rsa_key(timestamp):
        rsa_key_private= ''
        rsa_key_private_passphrase= ''
        return rsa_key_private , rsa_key_private_passphrase


class SecureEnough(object):
    config_app_secret= None
    config_obfuscation= None
    config_rsa= None

    app_secret= ''

    use_rsa_encryption = False
    rsa_key_private= None
    rsa_key_private_passphrase= None

    use_obfuscation= False
    obfuscation_secret = ''
    obfuscation_key = ''

    def __init__( self ,
            config_app_secret=None ,
            app_secret='' , 

            use_rsa_encryption=True , 
            config_rsa= None,
            rsa_key_private=None , 
            rsa_key_private_passphrase=None , 

            use_obfuscation=True ,
            config_obfuscation=None,
            obfuscation_secret='' , 
            obfuscation_key= None
        ):
        if config_app_secret:
            factory_app_secret= config_app_secret
        else:
            self.app_secret= app_secret

        if use_rsa_encryption:
            self.use_rsa_encryption= use_rsa_encryption
            if config_rsa:
                self.config_rsa= config_rsa
            else:
				self.rsa_key_private= rsa_key_private
				if rsa_key_private_passphrase:
					self.rsa_key_private_passphrase= rsa_key_private_passphrase
					self._rsa_key= RSA.importKey( self.rsa_key_private , rsa_key_private_passphrase )
				else:
					self._rsa_key= RSA.importKey(self.rsa_key_private)
				self._rsa_key_length_bytes= int((self._rsa_key.size() + 1) / 8)
				self._rsa_block_bytes=  self._rsa_key_length_bytes - 2 * 20 - 2 # from oaep.py
				self._rsa_padder= OAEP(os.urandom)
        if use_obfuscation:
            self.use_obfuscation= use_obfuscation
            if config_obfuscation: 
                self.config_obfuscation= config_obfuscation
            else:
				self.obfuscation_secret= obfuscation_secret
				self.obfuscation_key = obfuscation_key
				if not obfuscation_key:
				    self.obfuscation_key = hashlib.sha512(obfuscation_secret).digest() + hashlib.sha512(obfuscation_secret[::-1]).digest()


    @classmethod
    def base64_url_encode(cls,text):
        """this is just wrapping base64.urlsafe_b64encode , to allow for a later switch"""
        padded_b64 = base64.urlsafe_b64encode(text)
        return padded_b64.replace('=', '') # = is a reserved char

    @classmethod
    def base64_url_decode(cls,inp):
        """this is essentially wrapping base64.base64_url_decode , to allow for a later switch"""
        padding_factor = (4 - len(inp) % 4) % 4
        inp += "=" * padding_factor 
        return base64.urlsafe_b64decode(inp)
        
    @classmethod
    def _digestmod(cls, algorithm):
        if algorithm == 'HMAC-SHA256':
            digestmod= hashlib.sha256
        else:
            raise ValueError("unsupported algorithm")
        return digestmod

    @classmethod
    def signed_request_create( cls , data , secret=None , timeout=None , algorithm="HMAC-SHA256" ):
        digestmod= cls._digestmod(algorithm)
        data['algorithm'] = algorithm
        payload= cls.base64_url_encode( json.dumps(data) )
        signature= hmac.new( secret , msg=payload , digestmod=digestmod ).hexdigest()
        return signature + '.' + payload


    @classmethod
    def signed_request_verify( cls , signed_request=None , secret=None , timeout=None , algorithm="HMAC-SHA256" ):
        """This is compatible with signed requests from facebook.com (https://developers.facebook.com/docs/authentication/signed_request/) 
        
        returns a tuple of (Boolean,Dict), where Dict is the Payload and Boolean is True/False based on an optional timeout.  Raises an "Invalid" if a serious error occurs. """
        digestmod= cls._digestmod(algorithm)
        (signature,payload)= signed_request.split('.')

        decoded_signature = cls.base64_url_decode(signature)
        payload_decoded= cls.base64_url_decode(payload)
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


    def obfuscate( self , text ):
        # copy out our OBFUSCATE_KEY to the length of the text
        key = self.obfuscation_key * (len(text)//len(self.obfuscation_key) + 1)
        # XOR each character from our input with the corresponding character from the key
        xor_gen = (chr(ord(t) ^ ord(k)) for t, k in zip(text, key))
        return ''.join(xor_gen)
        
    
    def encode_payload( self , data ):
        serialized = self._serialize( data )
        signature = hmac.new( self.app_secret , serialized , hashlib.sha1 ).hexdigest()
        if self.use_obfuscation:
            obfuscated=  self.obfuscate( serialized )
            return obfuscated
        else:
            return serialized

    
    def decode_payload( self , serialized ):
        if self.use_obfuscation :
            deobfuscated=  self.obfuscate( serialized )
            data= self._deserialize(deobfuscated)
        else:
            data= self._deserialize(serialized)
        return data

        
    def _hmac_for_time(self,payload,time_now,algorithm="HMAC-SHA256" ):
        digestmod= self._digestmod(algorithm)
        message= "%s||%s" % ( payload , time_now ) 
        return hmac.new( self.app_secret , msg=message , digestmod=digestmod ).hexdigest()


    def encrypt(self,data,hashtime=True):
        payload= self.encode_payload(data)
        if self.use_rsa_encryption:
            payload = self.rsa_encrypt(payload)
        payload= self.base64_url_encode(payload)
        if hashtime:
            time_now= int(time())
            hash= self._hmac_for_time(payload,time_now)
            compound= "%s|%s|%s" % ( payload , time_now , hash )
            return compound
        return payload

    def decrypt(self,payload,hashtime=True,timeout=None):
        if hashtime :
            ( payload , time_then , hash_received )= payload.split('|')
            hash_expected= self._hmac_for_time( payload , time_then )
            if hash_expected != hash_received:
                raise InvalidChecksum()
            if timeout:
                time_now= int(time())
                if ( (time_now - time_then) > timeout ) :
                    raise InvalidTimeout()

        payload = self.base64_url_decode(payload)
        if self.use_rsa_encryption:
            payload = self.rsa_decrypt(payload)
        payload = self.decode_payload(payload)

        return payload

    def rsa_encrypt(self,s):
        encrypted_blocks = []
        for block in self.rsa_split_string(s, self._rsa_block_bytes):
            padded_block = self._rsa_padder.encode(self._rsa_key_length_bytes, block) # will raise ValueError if token is too long
            encrypted_block = self._rsa_key.encrypt(padded_block, None)[0]
            encrypted_blocks.append(encrypted_block)
        return ''.join(encrypted_blocks)
        
    def rsa_decrypt(self,s):
        decrypted_blocks = []
        for block in self.rsa_split_string(s, self._rsa_key_length_bytes):
            padded_block = '\x00' + self._rsa_key.decrypt(block) # NUL byte is apparently dropped by decryption
            decrypted_block = self._rsa_padder.decode(self._rsa_key_length_bytes, padded_block) # will raise ValueError on corrupt token
            decrypted_blocks.append(decrypted_block)
        return ''.join(decrypted_blocks)

    def rsa_split_string(self,s, block_size):
        blocks = []
        start = 0
        while start < len(s):
            block = s[start:start+block_size]
            blocks.append(block)
            start += block_size
        return blocks
    

