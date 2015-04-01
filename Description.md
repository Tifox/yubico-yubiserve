This simple service allows to authenticate Yubikeys and OATH/HOTP Tokens using
only a small sqlite database (the mysql support is optional!).
The code has been released under GNU license (license into LICENSE file)

The project is divided into two parts:
  * The database management tool (dbconf.py)
  * The validation server (yubiserve.py)

## The database management tool ##
The database management tool helps you to manage keys in the database.
For detailed help, run the database management tool with ./dbconf.py

The tool allows you to add, delete, disable, enable and show keys/tokens.
You can also add, remove and show API keys, to check the server signature in
server responses.
Everything is managed through nicknames, to make keys easy to remember
who belong to.

**For example, to add a new yubikey, write:**
```
./dbconf.py -ya alessio vvkdtkjureru 980a8608b307 f1dc9c6585d600d06f9aae1abea2969e
```

In this example, 'alessio' is the key nickname, 'vvkdtkjureru' is the
key public identity (the one you can see at the beginning of your OTPs),
'980a8608b307' is the private identity of the OTP (you can read it when
you program your key), and the last parameter is the AES Key.


**To add a new OATH/HOTP:**
```
./dbconf.py -ha alessio 4rvn24642402 f03ddacdfebb6396f60d7045f41de68f5c5e1c3f
```

In this other example, 'alessio' is still the nickname, '4rvn24642402' is
the public identity of the token (it could be also 1, 2, 'alessio' or
whatever you want; the Yubico implementation is 12 characters long)


**To add a new API key:**
```
./dbconf.py -aa alessio
```

When you add a new API key, the configuration tool will return both
the api key (ex. 'UkxFMnNFNTV4clRYUExSOWlONzQ=') and the API key id
meant to be used later in your queries to the Yubiserve validation server.



## The Yubiserve Validation Server ##
Understanding how to use the Yubiserve web application is pretty simple.
You just have to run it (./yubiserve.py) and send your queries through
HTTP (or HTTPS if you prefer) GET connections.

The default HTTP listening port is 8000, the default listening ip is 0.0.0.0
(so you can connect to it from other machines).
To use the HTTPS/SSL support, the default port will be 8001.

If you need it to answer only from local machine, you can change the ip to 127.0.0.1; if you want, you can also change the port. Just open the file 'yubiserve.conf', and change the following lines:
```
yubiservePORT = 8000;
yubiserveSSLPORT = 8001;
yubiserveHOST = '0.0.0.0';
```

Ex.:
```
yubiservePORT = 80;
yubiserveSSLPORT = 443;
yubiserveHOST = '127.0.0.1';
```

This way it will answer on default HTTP port 80, the HTTPS on port 443, on localhost only. Of course, you must make sure the port is available and not already being used by something else (like Apache)!

When you connect to the server (ex. http://192.168.0.1:8000/), it will
answer with a simple page, asking you Yubico Yubikeys OTPs or OATH/HOTP
tokens.


The Yubico Yubikey needs only one parameter: the OTP.

The OATH/HOTP tokens needs two parameters: the OTP itself (6 or 8 digits)
and the Token Identifier. The token identifier can be any character string
you prefer, or, according to the standard OATH implementation, the preceding
string to the OTP. The Yubico implementation follows this standard.
The Yubiserve Validation Server, according to the standard, will try to
find the Token Identifier preceding the OTP. If the string is found, the
OTP will be verified according to that string; in case of LCD tokens,
the string is not automatically added, so you will need to insert your ID
in the second box to allow the Validation Server to find your own identity.