#!/usr/bin/env python

class YubiserveDB():
   conn      = None
   cur       = None

   def __init__(self, mysqlhost, mysqluser, mysqlpass, mysqldb, dbtype = 'sqlite'):
      self.dbtype = dbtype
      self.mysqlhost = mysqlhost
      self.mysqluser = mysqluser
      self.mysqlpass = mysqlpass
      self.mysqldb = mysqldb
   """if self.dbtype == 'mysql':
      global MySQLdb
      try:
         import MySQLdb
      except ImportError:
         raise Exception, 'Cannot import MySQLdb. Did you install the python support for MySQL? Have you read the README?'
   elif self.dbtype == 'sqlite':
      global sqlite
      try:
         import sqlite3
         self.dbtype = 'sqlite3'
      except ImportError:
         try:
            import sqlite
            self.dbtype = 'sqlite'
         except ImportError:
            raise Exception, 'Cannot import sqlite/sqlite3. Did you install the python for sqlite/sqlite3? Have you read the README?'"""
   
   def query(self, query, commit = False):
      if self.conn == None:
         if self.dbtype == 'mysql':
            self.conn = MySQLdb.connect(host=self.mysqlhost, user=self.mysqluser, passwd=self.mysqlpass, db=self.mysqldb)
         elif self.dbtype == 'sqlite':
            self.conn = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite', check_same_thread = False)
         elif self.dbtype == 'sqlite3':
            self.conn = sqlite3.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite3', check_same_thread = False)
         self.cur  = self.conn.cursor()
      try:
         self.cur.execute(query)
      except Exception, e:
         print 'Unhandled exception: ' + e
         pass
      retval = self.cur.fetchone()
      if commit:
         self.conn.commit()
      return retval
   
   def close():   # This is called at the end of token testing
      self.cur.close()
      self.conn.close()
      self.cur = None
      self.conn = None
