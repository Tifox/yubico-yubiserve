class HTTPHandler (BaseHTTPServer.BaseHTTPRequestHandler):
   __base = BaseHTTPServer.BaseHTTPRequestHandler
   __base_handle = __base.handle
   server_version = 'Yubiserve/3.1'
   global config
   #try:
   if config['yubiDB'] == 'sqlite3':
      con = sqlite3.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite3', check_same_thread = False)
   elif config['yubiDB'] == 'sqlite':
      con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite', check_same_thread = False)
   elif config['yubiDB'] == 'mysql':
      con = DB()
   #except:
   #       print "There's a problem with the database!\n"
   #       sys.exit(1)
   
   def __init__(self, version):
      self.server_version = version
   
   def _getToDict(self, qs):
      dict = {}
      for singleValue in qs.split('&'):
         keyVal = singleValue.split('=')
         # Validation of input
         if keyVal[0] in ['otp','nonce','id','publicid','service'] and len(keyVal[1]) > 0:
            if keyVal[0] not in dict:
               dict[keyVal[0]] = urllib.unquote_plus(keyVal[1])
         else:
            if len(keyVal[0]) > 0:
               print "Invalid param '%s=%s' passed to yubiserve" % (keyVal[0],keyVal[1])
            else:
               pass    
      return dict
      
   def _setup(self):
      self.connection = self.request
      self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
      self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
      
   def log_message(self, format, *args): # To be implemented into logging
      pass
      
   def do_GET(self):
      (scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')
      if scm != 'http':
         self.send_error(501, "The server does not support the facility required.")
         return
      if path == '/wsapi/2.0/verify': # Yubico Yubikey
         try:
            if len(query) > 0:
               getData = self.getToDict(query)
               otpvalidation = OTPValidation(self.con)
               validation = otpvalidation.validateOTP(getData['otp'])
               self.send_response(200)
               self.send_header('Content-type', 'text/plain')
               self.end_headers()
               iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
               try:
                  result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=' + getData['nonce'] + '\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
                  orderedResult = 'nonce=' + getData['nonce'] + '&otp=' + getData['otp'] + '&sl=100&status=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '&t=' + iso_time
               except KeyError:
                  result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
                  orderedResult = 'nonce=&otp=' + getData['otp'] + '&sl=100&status=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '&t=' + iso_time
               otp_hmac = ''
               try:
                  if (getData['id'] != None):
                     apiID = re.escape(getData['id'])
                     cur = self.con.cursor()
                     cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                     res = cur.fetchone()
                     if res:
                        api_key = res[0]
                        otp_hmac = hmac.new(str(api_key), msg=str(orderedResult), digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
                     else:
                        result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nstatus=NO_CLIENT\r\n'
               except KeyError:
                  pass
               self.wfile.write('h=' + otp_hmac + '\r\n' + result + '\r\n')
               return
         except KeyError:
            pass
         self.send_response(200)
         self.send_header('Content-type', 'text/plain')
         self.end_headers()
         iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
         result = 't=' + iso_time + '\r\notp=\r\nnonce=\r\nstatus=MISSING_PARAMETER\r\n'
         orderedResult = 'nonce=&otp=&status=MISSING_PARAMETER&t=' + iso_time
         otp_hmac = ''
         try:
            if (getData['id'] != None):
               apiID = re.escape(getData['id'])
               cur = self.con.cursor()
               cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
               res = cur.fetchone()
               if res:
                  api_key = res[0]
                  otp_hmac = hmac.new(api_key, msg=orderedResult, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
         except KeyError:
            pass
         self.wfile.write('h=' + otp_hmac + '\r\n' + result + '\r\n')
         return
      elif path == '/wsapi/2.0/oathverify': # OATH HOTP
         try:
            getData = self.getToDict(query)
            if (len(query) > 0) and ((len(getData['otp']) == 6) or (len(getData['otp']) == 8) or (len(getData['otp']) == 18) or (len(getData['otp']) == 20)):
               oathvalidation = OATHValidation(self.con)
               OTP = getData['otp']
               if (len(OTP) == 18) or (len(OTP) == 20):
                  publicID = OTP[0:12]
                  OTP = OTP[12:]
               elif (len(OTP) == 6) or (len(OTP) == 8):
                  if len(getData['publicid'])>0:
                     publicID = getData['publicid']
                  else:
                     raise KeyError
               
               validation = oathvalidation.validateOATH(OTP, publicID)
               self.send_response(200)
               self.send_header('Content-type', 'text/plain')
               self.end_headers()
               iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
               result = 'otp=' + getData['otp'] + '\r\nstatus=' + [k for k, v in oathvalidation.status.iteritems() if v == validation][0] + '\r\nt=' + iso_time
               otp_hmac = ''
               try:
                  if (getData['id'] != None):
                     apiID = re.escape(getData['id'])
                     cur = self.con.cursor()
                     cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                     res = cur.fetchone()
                     if res:
                        api_key = res[0]
                        otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
                     else:
                        result = 'otp=' + getData['otp'] + '\r\nstatus=NO_CLIENT\r\nt=' + iso_time
               except KeyError:
                  pass
               self.wfile.write(result + '\r\nh=' + otp_hmac)
               return
            else:
               self.send_response(200)
               self.send_header('Content-type', 'text/plain')
               self.end_headers()
               iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
               result = 'otp=\r\nstatus=BAD_OTP\r\nt=' + iso_time
               otp_hmac = ''
               try:
                  if (getData['id'] != None):
                     apiID = re.escape(getData['id'])
                     cur = self.con.cursor()
                     cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                     res = cur.fetchone()
                     if res:
                        api_key = res[0]
                        otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
               except KeyError:
                  pass
               self.wfile.write('h=' + otp_hmac + '\r\n' + result)
               return
         except KeyError:
            pass
         self.send_response(200)
         self.send_header('Content-type', 'text/plain')
         self.end_headers()
         iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
         result = 'otp=\r\nstatus=MISSING_PARAMETER\r\nt=' + iso_time
         otp_hmac = ''
         try:
            if (getData['id'] != None):
               apiID = re.escape(getData['id'])
               cur = self.con.cursor()
               cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
               res = cur.fetchone()
               if res:
                  api_key = res[0]
                  otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
         except KeyError:
            pass
         self.wfile.write('h=' + otp_hmac + '\r\n' + result)
         return
      else:
         self.send_response(200)
         self.send_header('Content-type', 'text/html')
         self.end_headers()
         self.wfile.write('<html>')
         # Yubico Yubikey
         self.wfile.write('Yubico Yubikeys:<br><form action="/wsapi/2.0/verify" method="GET"><input type="text" name="otp"><br><input type="submit"></form><br>')
         # OATH HOTP
         self.wfile.write('OATH/HOTP tokens:<br><form action="/wsapi/2.0/oathverify" method="GET"><input type="text" name="otp"><br><input type="text" name="publicid"><br><input type="submit"></form>')
         self.wfile.write('</html>')
   do_HEAD    = do_GET
   do_PUT     = do_GET
   do_DELETE       = do_GET
   do_CONNECT      = do_GET
   do_POST    = do_GET