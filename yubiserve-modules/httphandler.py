#!/usr/bin/env python
from yubiserve-modules import configparser
from yubiserve-modules import db
from yubiserve-modules import response

class HTTPHandler (BaseHTTPServer.BaseHTTPRequestHandler):
   __base = BaseHTTPServer.BaseHTTPRequestHandler
   __base_handle = __base.handle
   server_version = None
   database = None
   do_HEAD = do_GET
   do_PUT = do_GET
   do_DELETE = do_GET
   do_CONNECT = do_GET
   do_POST = do_GET   
   def __init__(self, version):
      global config
      self.server_version = version
      #config = config_parse()    # Into the main file!
      self.database = YubiserveDB(config.yubiDB, config.yubiMySQLHost, config.yubiMySQLUser, config.yubiMySQLPass, config.yubiMySQLName)
   def _get_to_dict(self, qs):
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
      
   def log_message(self, format, *args):     # To be implemented into logging
      pass
      
   def do_GET(self):
      (scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')
      if scm != 'http':
         self.send_error(501, "The server does not support the facility required.")
         return
      if path == '/wsapi/2.0/verify':        # Yubico Yubikey
         get_data = self.getToDict(query)
         self.send_response(200)
         self.send_header('Content-type', 'text/plain')
         self.end_headers()
         response = ResponseGenerator(self.database, get_data, 'yubico')
         self.wfile.write(response + '\r\n')
      elif path == '/wsapi/2.0/oathverify':  # OATH (TOTP/HOTP)
         get_data = self.getToDict(query)
         self.send_response(200)
         self.send_header('Content-type', 'text/plain')
         self.end_headers()
         if not 'totp' in get_data:
            response = ResponseGenerator(self.database, get_data, 'HOTP')
         else:
            response = ResponseGenerator(self.database, get_data, 'TOTP'
         self.wfile.write(response + '\r\n')
      elif path == '/wsapi/2.0/backupotp':   # Password OTP backup
         get_data = self.getToDict(query)
         self.send_response(200)
         self.send_header('Content-type', 'text/plain')
         self.end_headers()
         response = ResponseGenerator(self.database, get_data, 'BackupPass')
         self.wfile.write(response + '\r\n')
      elif path == '/healthcheck':
         pass                                # To be added
      else:
         self.send_response(404)
         self.send_header('Content-type', 'text/html')
         self.end_headers()
         self.wfile.write('Yubico Yubiserve. No template has been found.')
      self.database.close()                  # Close the database to save resources
