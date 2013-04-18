#!/usr/bin/env python
class OTPValidation():
	def __init__(self, connection):
		self.status = {'OK': 1, 'BAD_OTP': 2, 'REPLAYED_OTP': 3, 'DELAYED_OTP': 4, 'NO_CLIENT': 5, 'ERROR': 6}
		self.validationResult = 0
		self.database = None
	def _hexdec(self, hex):
		return int(hex, 16)
	def _modhex2hex(self, string):
		hex = "0123456789abcdef"
		modhex = "cbdefghijklnrtuv"
		retVal = ''
		for i in range (0, len(string)):
			pos = modhex.find(string[i])
			if pos > -1:
				retVal += hex[pos]
			else:
				raise Exception, '"' + string[i] + '": Character is not a valid hex string'
		return retVal
	def _CRC(self):
		crc = 0xffff;
		for i in range(0, 16):
			b = self.hexdec(self.plaintext[i*2] + self.plaintext[(i*2)+1])
			crc = crc ^ (b & 0xff)
			for j in range(0, 8):
				n = crc & 1
				crc = crc >> 1
				if n != 0:
					crc = crc ^ 0x8408
		self.OTPcrc = crc
		return [crc]
	def _isCRCValid(self):
		return (self.OTPcrc == 0xf0b8)
	def _aes128ecb_decrypt(self, aeskey, aesdata):
		return AES.new(aeskey.decode('hex'), AES.MODE_ECB).decrypt(aesdata.decode('hex')).encode('hex')
	def getResult(self): # What is this?!
		return self.validationResult
	def getResponse(self): # What is this?!
		return self.validationResponse
	def validateOTP(self, OTP):
		global config
		self.OTP = re.escape(OTP)
		self.validationResult = 0
		if (len(OTP) <= 32) or (len(OTP) > 48):
			self.validationResult = self.status['BAD_OTP']
			return self.validationResult
		match = re.search('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})', re.escape(OTP))
		if match == None:
			print "OTP does not match expected syntax.\n"
			sys.stdout.flush()
			self.validationResult = self.status['BAD_OTP']
			return self.validationResult

		try:
			if match.group(1) and match.group(2):
				self.userid = match.group(1)
				self.token = self.modhex2hex(match.group(2))
				# pdb.set_trace()
				cur = self.con.cursor()
				cur.execute('SELECT aeskey, internalname FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "1"')
				res = cur.fetchone()
				if not res:
					if config['yubiserveDebugLevel'] > 0:
						print "Yubikey rejected because it is not found in the database, using the query: 'SELECT aeskey, internalname FROM yubikeys WHERE publicname = \"%s\" AND active = \"1\"'" % (self.userid)
					self.validationResult = self.status['BAD_OTP']
					return self.validationResult
				(self.aeskey, self.internalname) = res
				self.plaintext = self.aes128ecb_decrypt(self.aeskey, self.token)
				uid = self.plaintext[:12]
				if (self.internalname != uid):
					if config['yubiserveDebugLevel'] > 0:
						print "Yubikey rejected because the uid (6 byte secret) in the decrypted AES key (set with with ykpersonalise -ouid) does not match the secret key (internalname) in the database"
						print "Decrypted AES: %s\n Username from yubikey: %s should equal the database username: %s" % (self.plaintext, uid, self.internalname)
					self.validationResult = self.status['BAD_OTP']
					return self.validationResult
				if not self.CRC() or not self.isCRCValid():
					self.validationResult = self.status['BAD_OTP']
					return self.validationResult
				self.internalcounter = self.hexdec(self.plaintext[14:16] + self.plaintext[12:14] + self.plaintext[22:24])
				self.timestamp = self.hexdec(self.plaintext[20:22] + self.plaintext[18:20] + self.plaintext[16:18])
				cur.execute('SELECT counter, time FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "1"')
				res = cur.fetchone()
				if not res:
					self.validationResult = self.status['BAD_OTP']
					return self.validationResult
				(self.counter, self.time) = res
				if (self.counter) >= (self.internalcounter):
					self.validationResult = self.status['REPLAYED_OTP']
					return self.validationResult
				if (self.time >= self.timestamp) and ((self.counter >> 8) == (self.internalcounter >> 8)):
					self.validationResult = self.status['DELAYED_OTP']
					return self.validationResult
		except IndexError:
			self.validationResult = self.status['BAD_OTP']
			return self.validationResult
		self.validationResult = self.status['OK']
		cur.execute('UPDATE yubikeys SET counter = ' + str(self.internalcounter) + ', time = ' + str(self.timestamp) + ' WHERE publicname = "' + self.userid + '"')
		self.con.commit()
		return self.validationResult
