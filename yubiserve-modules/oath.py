#!/usr/bin/env python
#
# Parts of this implementation has been borrowed from the hotpie project
# available on GitHub: https://github.com/gingerlime/hotpie
#

import hmac, hashlib, array, time, unittest

class OATHValidation():
   validationResult = 0
   database = None
   def __init__(self, database):
      self.status = {'OK': 1, 'BAD_OTP': 2, 'NO_AUTH': 3, 'NO_CLIENT': 5, 'ERROR': 6}
      self.validationResult = 0
      self.database = database
      return self
      
   def _HOTP(self, K, C):
      C_bytes = _long_to_byte_array(C)
      hmac_sha1 = hmac.new(key=K, msg=C_bytes, digestmod=hashlib.sha1).hexdigest()
      return self._truncate(hmac_sha1)[-len(C):]
   
   def _TOTP(self, K, window=30): # window = time window
      C = long(time.time() / window)
      return HOTP(K, C)
   
   def _truncate(string):
      offset = int(hmac_sha1[-1], 16)
      binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
      return str(binary)
   
   def _long_to_byte_array(long_num): # It can be probably simplified with python's structs!
      byte_array = array.array('B')
      for i in reversed(range(0, 8)):
         byte_array.insert(0, long_num & 0xff)
         long_num >>= 8
      return byte_array
   
   def validateOATH(self, OATH, publicID, hotp = True, timewindow=30): # By default, we check for HOTP (backward compatibility too)
      res = database.query("SELECT counter, secret FROM oathtokens WHERE publicname = '" + publicID + "' AND active = '1'")
      if not res:
         validationResult = self.status['BAD_OTP']
         return validationResult
      (actualcounter, key) = res
      if len(OATH) % 2 != 0:
         self.validationResult = self.status['BAD_OTP']
         return self.validationResult
      K = key.decode('hex') # key in ascii
      if hotp == True:
         for C in range(actualcounter+1, actualcounter+256):
            if OATH == self._HOTP(K, C, len(OATH)):
               try:
                  retval = database.query("UPDATE oathtokens SET counter = " + str(C) + " WHERE publicname = '" + publicID + "' AND active = '1'", commit = True)
               except:
                  # An error has been raised, write it into the log and return fail!
                  return self.status['ERROR']
               if retval:
                  return self.status['OK']
               else:
                  return self.status['ERROR']
         return self.status['NO_AUTH']
      else: # so, time-based
         if OATH == self._TOTP(K, timewindow):
            return self.status['OK']
         else:
            return self.status['NO_AUTH']
   
   def validateBackup(self, code, publicID): # Use the one-time backup password and destroy it
      curdate = 
      res = database.query("UPDATE backuptokens SET date = DATETIME() WHERE publicname = '" + publicID + "' AND code = '" + code + "'", commit = True)
      if res:
         return (self.status['OK'], database.query("SELECT COUNT(*) FROM backuptokens WHERE publicname = '" + publicID + " AND date IS NULL")) # Return the remaining number of keys
      else:
         return (self.status['NO_AUTH'], -1)