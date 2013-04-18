#!/usr/bin/env python
import re
import hmac
import hashlib
from Crypto.Cypher import AES
from yubiserve-modules import db
from yubiserve-modules import yubico
from yubiserve-modules import oath

class ResponseGenerator():
   database = None
   def __init__(self, database, getdata, token):
      # getdata stands for "data from HTTP GET"
      # token stands for the token type (yubico, hotp, totp)
      
      iso_time = self._get_iso_time()
      self.database = database # TODO: Is it necessary to reinitialize it?
      otp = ''
      if 'otp' in getdata:
         otp = getdata['otp']
         if token == 'Yubico':
            if 'nonce' in getdata:
               nonce = getdata['nonce']
            else:
               nonce = ''
            yubico = OTPValidation(otp)
            status = [k for k, v in yubico.status.iteritems() if v == yubico.validateOTP(otp)][0]
            # Can't use just orderedResult for everything: some client softwares
            # expect to find it in the other order
            result = 't=%s\r\notp=%s\r\nnonce=%s\r\nsl=100\r\nstatus=%s\r\n' % (iso_time, otp, nonce, status)
            orderedResult = 'nonce=%s&otp=%s&sl=100&status=%s&t=%s' % (nonce, otp, status, iso_time) 
         elif token == 'HOTP':
            if not 'publicid' in getdata:
               result = 't=%s\r\notp=%s\r\npublicid=\r\nstatus=MISSING_PARAMETER\r\n' % (iso_time, otp)
               orderedResult = 'otp=%s&publicid=\r\nstatus=MISSING_PARAMETER&t=%s' % (iso_time, otp)
            else:
               oath = OATHValidation(database)
               publicid = getdata['publicid']
               status = [k for k, v in oath.status.iteritems() if v == oath.validateOATH(otp, publicid)][0]
               result = 't=%s\r\notp=%s\r\npublicid=%s\r\nstatus=%s\r\n' % (iso_time, otp, publicid, status)
               orderedResult = 'otp=%s&publicid=%s&status=%s&t=%s' % (otp, publicid, status, iso_time)
         elif token == 'TOTP':
            if not 'publicid' in getdata:
               result = 't=%s\r\notp=%s\r\npublicid=\r\nstatus=MISSING_PARAMETER\r\n' % (iso_time, otp)
               orderedResult = 'otp=%s&publicid=\r\nstatus=MISSING_PARAMETER&t=%s' % (iso_time, otp)
            else:
               oath = OATHValidation(database)
               publicid = getdata['publicid']
               status = [k for k, v in oath.status.iteritems() if v == oath.validateOATH(otp, publicid, hotp=False)][0]
               result = 't=%s\r\notp=%s\r\npublicid=%s\r\nstatus=%s\r\n' % (iso_time, otp, publicid, status)
               orderedResult = 'otp=%s&publicid=%s&status=%s&t=%s' % (otp, publicid, status, iso_time)
         elif token == 'BackupPass':
            if not 'publicid' in getdata:
               result = 't=%s\r\notp=%s\r\npublicid=\r\nstatus=MISSING_PARAMETER\r\n' % (iso_time, otp)
               orderedResult = 'otp=%s&publicid=\r\nstatus=MISSING_PARAMETER&t=%s' % (iso_time, otp)
            else:
               oath = OATHValidation(database)
               publicid = getdata['publicid']
               status = oath.validateBackup(otp, publicid, hotp=False)
               if status >= 0:
                  result = 't=%s\r\notp=%s\r\npublicid=%s\r\nstatus=OK\r\nremainingkeys=%s\r\n' % (iso_time, otp, publicid, status)
                  orderedResult = 'otp=%s&publicid=%s&remainingkeys=%s&status=OK&t=%s' % (otp, publicid, status, iso_time)
               else:
                  result = 't=%s\r\notp=%s\r\npublicid=%s\r\nstatus=NO_AUTH\r\nremainingkeys=%s\r\n' % (iso_time, otp, publicid, status)
                  orderedResult = 'otp=%s&publicid=%s&remainingkeys=%s&status=NO_AUTH&t=%s' % (otp, publicid, status, iso_time)
      else:
         otp = ''
         result = 't=%s\r\notp=\r\nstatus=BAD_OTP\r\n' % (iso_time)
         orderedResult = 'otp=&status=BAD_OTP&t=%s' % (iso_time)
      if 'id' in getdata:  # Sign the message if there's an api key
         signature = self._sign_message(database, orderedResult, getdata['id'])
         if signature:     # If the api key is valid
            result = 'h=%s\r\n%s' % (signature, result)
         else:
            result = 'h=\r\nt=%s\r\notp=%s\r\nstatus=NO_CLIENT\r\n' % (iso_time, otp)
      return result
      
   def _get_iso_time(self):
      return time.strftime("%Y-%m-%dT%H:%M:%S")
	def validate_hmac(self, hmac):
      # check for hmac validation, issue #14
      pass
   def _sign_message(self, database, message, api_key):
      api_id = re.escape(getData['id'])
      res = database.query('SELECT secret from apikeys WHERE id = "%s"' % (api_id))
      if res:
         api_key = res[0]
         signature = hmac.new(str(api_key), msg=str(message), digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
         return signature
      else:
         return 0
