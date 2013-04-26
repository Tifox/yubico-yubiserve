#!/usr/bin/env python
def config_parse():   # Originally I wrote this function to parse PHP configuration files!
   config = open(os.path.dirname(os.path.realpath(__file__)) + '/yubiserve.cfg', 'r').read().splitlines()
   keys = {}
   for line in config:
      match = re.search('(.*?)=(.*);', line)
      try: # Check if it's a string or a number
         if ((match.group(2).strip()[0] != '"') and (match.group(2).strip()[0] != '\'')):
            keys[match.group(1).strip()] = int(match.group(2).strip())
         else:
            keys[match.group(1).strip()] = match.group(2).strip('"\' ')
      except:
         pass
   return keys
