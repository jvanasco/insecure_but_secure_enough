"""

This package is insecure, but secure enough.

The idea for secure_enough to allow for "autologin cookies" and "instant login" urls for stupid social web applications.

Two important things to note:

    1. You should not use this module for financial transactions or sensitive info.  That would be egregiously stupid.
    2. If you log someone in with this , you should note the login as "insecure" and require them to provide a password to view sensitive data or any 'write' activity.


This package supports the following schemes for encrypting data:

1. RSA encryption (really!)
2. AES encryption

This package supports the following schemes for signing data:

1. No signing ( just serialize )
2. HMAC SHA1 signing
3. HMAC SHA256 signing
4. Request signing, as compatible with Facebook's auth scheme.
	
The data transformation is as follows :

1. serialize ( convert to JSON )
2. base64 encode
3. ? obfuscate
4. ? encrypt
5. ? sign
	
UNTESTED

* You can create "configuration objects" that accept a timestamp and return an appropriate secret/encryption key

===================


There is a bit of documentation in:
	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/insecure_but_secure_enough/__init__.py

The following files give an interactive demo:

	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo.py
	https://github.com/jvanasco/insecure_but_secure_enough/blob/master/demo_performance.py

Also note that the github source distribution contains tests.

===================

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

Check demo.py to see an overview of how this works.


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

===========





===========



# ToDo:

The timebased providers is entirely untested.  I need to build out the demo and the test suite to support it.

/__init__.py is released under the MIT license


"""


import base64
import hashlib
import hmac
from time import time
import types
import os

try :
    import simplejson as json
except ImportError:
    import json

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import atfork

from Crypto.Cipher import PKCS1_OAEP


class Invalid(Exception):
    """Base class you can catch"""
    pass

class InvalidAlgorithm(Invalid):
    """Raised when a secret it too old"""
    pass

class InvalidChecksum(Invalid):
    """the checksums do not match"""
    pass

class InvalidPayload(Invalid):
    """Raised when a payload can't be decoded"""
    pass

class InvalidSignature(Invalid):
    """the signature does not match"""
    pass

class InvalidTimeout(Invalid):
    """Raised when a signature is too old"""
    pass



class AesCipherHolder(object):
    """wraps an AES Symmetric Cipher"""
    _secret = None
    _cipher = None
    _aes_key = None
    _aes_iv = None
    
    def __init__( self , secret ):
        self._secret = secret

        # compute a 32-byte key
        self._aes_key = hashlib.sha256(self._secret).digest()
        assert len(self._aes_key) == 32

        # compute a 16-byte initialization vector
        self._aes_iv = hashlib.md5(self._secret).digest()
        assert len(self._aes_iv) == 16
        
    def cipher(self):
        # create an AES cipher
        # use CFB mode to avoid padding workflow
        cipher = AES.new( self._aes_key, AES.MODE_CFB, self._aes_iv )
        return cipher
        
    def encrypt( self, bytes ):
        return self.cipher().encrypt(bytes)

    def decrypt( self , bytes ):
        return self.cipher().decrypt(bytes)
    



class RsaKeyHolder(object):
    """wraps an RSA key"""
    key= None
    _key_private= None
    _key_private_passphrase= None
    
    key_length_bytes= None
    block_bytes= None
    cipher = None

    def __init__( self , key_private=None , key_private_passphrase=None ):
        self._key_private = key_private
        self._key_private_passphrase = key_private_passphrase
        if self._key_private_passphrase:
            self.key= RSA.importKey( self._key_private , self._key_private_passphrase )
        else:
            self.key= RSA.importKey( self._key_private )
        self.key_length_bytes= int((self.key.size() + 1) / 8)
        self.block_bytes=  self.key_length_bytes - 2 * 20 - 2 # from https://bugs.launchpad.net/pycrypto/+bug/328027
        self.cipher = PKCS1_OAEP.new(self.key)

    def encrypt(self,s):
        encrypted_blocks = []
        for block in self.split_string(s, self.block_bytes):
            encrypted_block = self.cipher.encrypt(block)
            encrypted_blocks.append(encrypted_block)
        return ''.join(encrypted_blocks)

    def decrypt(self,s):
        decrypted_blocks = []
        for block in self.split_string(s, self.key_length_bytes):
            decrypted_block = self.cipher.decrypt(block)
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

    def aes_cipher(timestamp):
        """for a given timestamp, this should return the appropriate AES object"""
        aes_secret = ''
        return AesCipherHolder( aes_secret )



class SecureEnough(object):
    use_aes_encryption = False
    use_obfuscation = False
    use_rsa_encryption = False

    
    # storage
    _config_provider_aes = None
    _config_provider_app_secret = None
    _config_provider_obfuscation = None
    _config_provider_rsa = None

    _app_secret = None
    _aes_cipher = None
    _obfuscator = None
    _rsa_key = None

    def __init__( self ,
            config_app_secret=None ,
            app_secret='' ,

            use_aes_encryption=False ,
            config_aes= None,
            aes_secret=None ,

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
            self._config_provider_app_secret = config_app_secret
        else:
            self._app_secret = app_secret

        if use_aes_encryption:
            if not any((config_aes,aes_secret)):
                raise ValueError("Must submit one of: aes_secret, config_aes")
            self.use_aes_encryption = use_aes_encryption
            if config_aes :
                self._config_provider_aes = config_aes
            else:
                self._aes_cipher= AesCipherHolder( aes_secret )

        if use_rsa_encryption:
            self.use_rsa_encryption= use_rsa_encryption
            if config_rsa:
                self._config_provider_rsa = config_rsa
            else:
                self._rsa_key= RsaKeyHolder( key_private = rsa_key_private , key_private_passphrase = rsa_key_private_passphrase )

        if use_obfuscation:
            self.use_obfuscation= use_obfuscation
            if config_obfuscation:
                self._config_provider_obfuscation= config_obfuscation
            else:
                self._obfuscator= Obfuscator( obfuscation_key , obfuscation_secret)



    def app_secret( self , timestamp=None ):
        """internal function to return an app secret"""
        if self._config_provider_app_secret :
            return self._config_provider_app_secret.app_secret(timestamp)
        return self._app_secret

    def aes_cipher( self , timestamp=None ):
        """internal function to return an aes cipher"""
        if self._config_provider_aes :
            return self._config_provider_aes.aes_cipher(timestamp)
        return self._aes_cipher

    def obfuscator( self , timestamp=None ):
        """internal function to return an obfuscator"""
        if self._config_provider_obfuscation :
            return self._config_provider_obfuscation.obfuscator(timestamp)
        return self._obfuscator

    def rsa_key( self , timestamp=None ):
        """internal function to return a rsa key"""
        if self._config_provider_rsa :
            return self._config_provider_rsa.rsa_key(timestamp)
        return self._rsa_key



    @classmethod
    def _base64_url_encode(cls,text):
        """internal classmethod for b64 encoding.  this is just wrapping base64.urlsafe_b64encode , to allow for a later switch"""
        padded_b64 = base64.urlsafe_b64encode(text)
        return padded_b64.replace('=', '') # = is a reserved char

    @classmethod
    def _base64_url_decode(cls,inp):
        """internal classmethod for b64 decoding. this is essentially wrapping base64.base64_url_decode , to allow for a later switch"""
        padding_factor = (4 - len(inp) % 4) % 4
        inp += "=" * padding_factor
        return base64.urlsafe_b64decode(inp)

    @classmethod
    def _digestmod(cls, algorithm=None):
        """internal class and instance method for returning an algoritm function"""
        if algorithm == 'HMAC-SHA256':
            digestmod= hashlib.sha256
        elif algorithm == 'HMAC-SHA1':
            digestmod= hashlib.sha1
        else:
            raise InvalidAlgorithm("unsupported algorithm - %s" % algorithm)
        return digestmod

    @classmethod
    def signed_request_create( cls , data , secret=None , issued_at=None , algorithm="HMAC-SHA256" ):
        """classmethod.  creates a signed token for `data` using `secret` , calculated by `algorithm`.  optionally include the `issued_at` 
            note that we use a copy of data -- as we need to stick the algorithm in there
        """
        _data = data.copy()
        digestmod= cls._digestmod(algorithm)
        if 'algorithm' in _data and _data['algorithm'] != algorithm :
            raise InvalidAlgorithm('`algorithm` defined in payload already , and as another format')
        _data['algorithm'] = algorithm
        if issued_at and 'issued_at' not in _data:
            _data['issued_at'] = issued_at
        payload= cls._base64_url_encode( json.dumps(_data) )
        signature= hmac.new( secret , msg=payload , digestmod=digestmod ).hexdigest()
        return signature + '.' + payload


    @classmethod
    def signed_request_verify( cls , signed_request=None , secret=None , timeout=None , algorithm="HMAC-SHA256" , payload_only=False ):
        """This is compatible with signed requests from facebook.com (https://developers.facebook.com/docs/authentication/signed_request/)

        returns a tuple of (Boolean,Dict), where Dict is the Payload and Boolean is True/False based on an optional timeout.  Raises an "Invalid" if a serious error occurs.

        if you submit the kwarg 'payload_only=True' , it will only return the extracted data .  No boolean will be returned.  If a timeout is also submitted, it will return the payload on success and False on failure.
        """
        digestmod= cls._digestmod(algorithm)

        (signature,payload)= signed_request.split('.')

        try:
            decoded_signature = cls._base64_url_decode(signature)
            payload_decoded= cls._base64_url_decode(payload)
            data = json.loads(payload_decoded)
        except json.JSONDecodeError , e :
            raise InvalidPayload( e.msg )
        except :
            raise InvalidPayload( "Can't decode payload (_base64 error?)" )

        if data.get('algorithm').upper() != algorithm:
            raise InvalidAlgorithm('unexpected algorithm.  Wanted %s , Received %s' % (algorithm,data.get('algorithm')) )

        expected_sig = hmac.new( secret , msg=payload , digestmod=digestmod ).hexdigest()

        if signature != expected_sig:
            raise InvalidSignature('invalid signature.  signature (%s) != expected_sig (%s)' % ( signature , expected_sig ) )

        if timeout:
            time_now= int(time())
            diff = time_now - data['issued_at']
            if ( diff > timeout ) :
                if payload_only:
                    return False
                return ( False , data )

        if payload_only:
            return data
        return ( True , data )


    def _serialize( self , data ):
        """internal function to serialize multiple data types for transmission"""
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
        """internal function to deserialize multiple data types from transmission"""
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
        """internal function. calcuates an hmac for a timestamp. to accomplish this, we just pad the payload with the given timestamp"""
        digestmod= self._digestmod(algorithm)
        message= "%s||%s" % ( payload , timestamp )
        app_secret= self.app_secret( timestamp=timestamp )
        return hmac.new( app_secret , msg=message , digestmod=digestmod ).hexdigest()



    def encode( self , data , hashtime=True , hmac_algorithm="HMAC-SHA1"):
        """public method. encodes data."""
        if hmac_algorithm and not hashtime:
            hashtime = True

        # compute the time, which is used for verification and coordinating the right secrets
        time_now= None
        if hashtime:
            time_now= int(time())

        # encode the payload , which serializes it and possibly obfuscates it

        # .. first we serialize it
        payload = self._serialize( data )

        # .. optionally include lightweight obfuscation
        if self.use_obfuscation:
            payload=  self.obfuscator( timestamp=time_now ).obfuscate( payload )

        # .. optionally encrypt the payload
        if self.use_rsa_encryption:
            payload = self.rsa_key( timestamp=time_now ).encrypt( payload )
        elif self.use_aes_encryption:
            payload = self.aes_cipher( timestamp=time_now ).encrypt( payload )

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
        """public method. decodes data."""
        if hmac_algorithm and not hashtime:
            hashtime = True

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
            payload = self.rsa_key( timestamp=time_then ).decrypt( payload )
        elif self.use_aes_encryption:
            payload = self.aes_cipher( timestamp=time_then ).decrypt( payload )

        if self.use_obfuscation :
            payload=  self.obfuscator(timestamp=time_then).deobfuscate( payload )

        payload = self._deserialize(payload)

        return payload



    def serialized_plaintext_encode( self , payload ):
        return self.encode( payload , hashtime=False , hmac_algorithm=None )

    def serialized_plaintext_decode( self , payload ):
        return self.decode( payload , hashtime=False , hmac_algorithm=None )

    def hmac_sha1_encode( self , payload ):
        return self.encode( payload , hashtime=True , hmac_algorithm="HMAC-SHA1" )

    def hmac_sha1_decode( self , payload ):
        return self.decode( payload , hashtime=True , hmac_algorithm="HMAC-SHA1" )

    def hmac_sha256_encode( self , payload ):
        return self.encode( payload , hashtime=True , hmac_algorithm="HMAC-SHA256" )

    def hmac_sha256_decode( self , payload ):
        return self.decode( payload , hashtime=True , hmac_algorithm="HMAC-SHA256" )


