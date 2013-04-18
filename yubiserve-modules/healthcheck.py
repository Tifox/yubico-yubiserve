#!/usr/bin/env python
      elif path == '/healthcheck': # Check system is healthy and database contains valid data.
         try:
            if len(query) > 0:
               getData = self.getToDict(query)
               if (getData['service'] == None):
                  print "Invalid query,  URL should be /healthchech?service=oathtokens|yubikeys"
                  check = 'all'
               else:
                  check = getData['service']
            else:
               check = 'all'
            response = ""
            code = "CRITICAL"
            cur = self.con.cursor()
            if check == 'all' or check == 'yubikeys':
               cur.execute('SELECT count(*) FROM yubikeys WHERE active = "1"')
               count = cur.fetchone()[0]
               if count < 1:
                  response += "No active yubikeys found\n"
                  code = "WARN"
               else:
                  code = "OK"
            if check == 'all' or check == 'oathtokens':
               cur.execute('SELECT count(*) FROM oathtokens WHERE active = "1"')
               count1 = cur.fetchone()[0]
               if count1 < 1:
                  response += "No active oathtokens found\n"
                  code = "WARN"
               else:
                  code = "OK"
            if check == 'all' and count <1 and count1 <1:
               self.send_response(503)
               code = "WARN"
            else:
               self.send_response(200)

            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(code + ": ")
            self.wfile.write(response)
         except Exception, e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write("CRITICAL: health check failed DB query\n")
            self.wfile.write("unhandled exception\n")
            self.wfile.write(repr(e))
         return