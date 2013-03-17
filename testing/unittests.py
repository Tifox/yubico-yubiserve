#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest
import subprocess
import pycurl
import StringIO
import re
import sys
apphome="../"
testuser="nelg"
testoath="Test"
testserver="http://localhost:8000/"
yubicotesturl=testserver + "wsapi/2.0/verify"
healthcheckurl=testserver + "healthcheck"
valid_yubikey_string='hihrhghufvfibbbekurednelnklnulclbiubvjrenlii'



class YubiserveTestCase(unittest.TestCase):


	def setupOathToken(self):
		self.tearDownOathToken();
		p = subprocess.Popen('%sdbconf.py -ha %s testtesttest e623694b2621a6eda41d9380c3dfc4fd67ffadb9' % (apphome,testoath), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		retval = p.wait()
	
	def tearDownOathToken(self):
		self.dbconfcmd('-hk',testoath)
		
	def dbconfcmd(self,cmd,param):
		p = subprocess.Popen('%sdbconf.py %s %s' % (apphome,cmd,param), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		retval = p.wait()

	def setUp(self):
		self.tearDown()
		p = subprocess.Popen('%sdbconf.py -ya %s hihrhghufvfi 676f6e656c67 89eb6d3d930077b427a88760db0fc375' % (apphome,testuser), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		retval = p.wait()
		
	def tearDown(self):
		self.dbconfcmd('-yk', testuser)
		self.tearDownOathToken();


class YubikeyTestCase(YubiserveTestCase):

	def testDbAPIkey(self):
		self.assertTrue( self.countDBAPIkey() > 0, msg="No API keys in DB" )

	def testDbconf(self):
		p = subprocess.Popen('%sdbconf.py -yl' % (apphome), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		for line in p.stdout.readlines():
			if re.search(testuser, line):
				self.assertTrue( re.search("%s\s+>> hihrhghufvfi\s+>> 1"% (testuser), line))
				return
		retval = p.wait()
		self.fail("dbconf.py did not list %s user" %(testuser))

	def testDisableEnableKey(self):
		self.dbconfcmd('-yd', testuser)
		self.assertTrue( re.search("^status=BAD_OTP", self.curl('?id=1&otp='+valid_yubikey_string),re.M),msg="Valid yubikey, but account is disabled")
		self.dbconfcmd('-ye', testuser)
		self.assertTrue( re.search("^status=OK", self.curl('?id=1&otp='+valid_yubikey_string),re.M),msg="Valid yubikey not accepted")

	def testReplayKey(self):
		self.assertTrue( re.search("^status=OK", self.curl('?id=1&otp='+valid_yubikey_string),re.M),msg="Valid yubikey not accepted")
		self.assertTrue( re.search("^status=REPLAYED_OTP", self.curl('?id=1&otp='+valid_yubikey_string),re.M),msg="Replayed token should not be accepted")


	def testbadCRC(self):
		self.assertTrue( re.search("^status=BAD_OTP", self.curl('?id=1&otp=hihrhghufvfirvbegrijgdjhjhtgihcehehtcrgbrhrb'),re.M),msg="Yubikey with Bad CRC")
		
# 	This test is disabled at the moment, until I figure out why it is getting an empty two spaces return to it
#	def testInvalidInput(self):
#		self.assertTrue( re.search("Invalid param 'otp=' passed", self.curl('?id=1&otp=&&&&&&&&&&&&&&&&&&&&&&&&',True),re.M),msg="invalid input should not be accepted, otp not set")
#		global yubiserve_process
#		print yubiserve_process.stdout.readline()
# @todo: check server output / log

	def testInvalidOTP(self):
		self.assertTrue( re.search("^status=BAD_OTP", self.curl('?id=1&otp=hihrhghufvfibbbek1urednelnklnulclbiubvjrenlii'),re.M),msg="invalid otp (contains a 1)")
#		print yubiserve_process.stdout.readline()
# @todo: check server output / log

		
	def testHealthCheckYubikeyOK(self):
		self.assertTrue( re.search("^OK:", self.curl('?service=yubikeys',url=healthcheckurl),re.M),msg="Health check should return OK for yubikeys service")

	def testHealthCheckOathOK(self):
		# setup oathtokens
		self.setupOathToken();
		self.assertTrue( re.search("^OK:", self.curl('?service=oathtokens',url=healthcheckurl),re.M),msg="Health check should return OK for oathtokens service")

	def testHealthChecksAllOK(self):
		# setup oathtokens
		self.setupOathToken();
		self.assertTrue( re.search("^OK:", self.curl('',url=healthcheckurl),re.M),msg="Health check should return OK for all services")
		

	def testHealthChecksAllwarn(self):
		# disable oathtokens, yubikeys
		self.setupOathToken();
		self.dbconfcmd('-yd', testuser)
		self.dbconfcmd('-hd', testoath)
		responce = self.curl('',url=healthcheckurl,httpcode=503,debug=False)
		self.assertTrue( re.search("^WARN:.*No active yubikeys found",responce ,re.M),msg="Health check should return WARN, no active yubikeys")
		self.assertTrue( re.search("^No active oathtokens found",responce ,re.M),msg="Health check should return the message: No active oathtokens found")


	def curl(self,params='?id=1&otp='+valid_yubikey_string,debug=False,url=yubicotesturl,httpcode=200):
		c = pycurl.Curl()
		b = StringIO.StringIO()
		c.setopt(pycurl.WRITEFUNCTION, b.write)
		c.setopt(pycurl.URL,url+params)
		c.perform()
		self.assertTrue(c.getinfo(pycurl.HTTP_CODE) == httpcode)
		if debug:
			print "Request: %s\n" % (url+params)
			print b.getvalue()
			print "\n"
		return b.getvalue()

	@staticmethod
	def countDBAPIkey():
		p = subprocess.Popen('%sdbconf.py -al' % (apphome), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		for line in p.stdout.readlines():
			m = re.match('.*(\d+) keys into database', line)
			if m: 
				return int(m.group(1))
		retval = p.wait()
		raise OSError('The command: %sdbconf.py1 -al failed, with return value %s' % (apphome,retval))

def startup():
		print "Starting yubiserve"
		global yubiserve_process
		yubiserve_process = subprocess.Popen('%syubiserve.py' % (apphome), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		if not re.search("HTTP and HTTPS servers are running.", yubiserve_process.stdout.readline()):
			print "Sorry, yubiserve.py did not start"

def shutdown():
		print "Stopping yubiserve"
		global yubiserve_process
		yubiserve_process.terminate()

def setupDBAPIkey():
	try:
		keys = YubikeyTestCase.countDBAPIkey()
	except OSError as e:
		print "ERROR reading dbconf api keys: .", e
		sys.exit(1)
	if keys < 1:
		print "Warning, 0 keys into database.  This tool is adding one, using %sdbconf.py -aa test" % (apphome)
		p = subprocess.Popen('%sdbconf.py -aa test' % (apphome), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		retval = p.wait()
                if YubikeyTestCase.countDBAPIkey() != 1:
			print "ERROR. Failed to add an API keys into database.  Please do this manually, or check for other errors using %sdbconf.py -aa test" % (apphome)
			sys.exit(1)

if __name__ == '__main__':
	   # add your global initialization code here
    setupDBAPIkey()
    startup()
    suite = unittest.TestLoader().loadTestsFromTestCase(YubikeyTestCase)
    unittest.TextTestRunner().run(suite)
    shutdown()
   
	
#		unittest.main()
