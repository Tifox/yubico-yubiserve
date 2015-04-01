Querying the Yubiserve Validation Server is pretty simple.
The following rules can be applied both to HTTP and HTTPS requests.

For Yubico Yubikeys, you will need to send a HTTP GET connection to:
```
http://<server ip>:<server port>/wsapi/2.0/verify?otp=<your otp>
ex.: http://192.168.0.1:8000/wsapi/2.0/verify?otp=vvnjbbkvjbcnhiretjvjfebbrdgrjjchdhtbderrdbhj
```
This way you will try to authenticate to it, the simplest way possible.
The response will be something like:

```
otp=vvnjbbkvjbcnhiretjvjfebbrdgrjjchdhtbderrdbhj
status=OK
t=2010-11-20T23:54:35
h=
```

As you can see, the 'h' parameter is not set, and this is because we didn't use
the signature through API Key. To use it, just add the 'id=<api key id>'
parameter we had when we added the API Key.
```
ex.: http://192.168.0.1:8000/wsapi/2.0/verify?otp=vvnjbbkvjbcnhiretjvjfebbrdgrjjchdhtbderrdbhj&id=1
```
This time the response will be like:

```
otp=vvnjbbkvjbcnhiretjvjfebbrdgrjjchdhtbderrdbhj
status=OK
t=2010-11-21T00:00:03
h=6lrhQPKo1I/RQA1KPnjpuiOvVMc=
```

To check the server signature, check the source code (you will have to do the
exact same procedure to generate it and then just check if they are equal), or
rely on the Yubico documentation on Validation Servers.

For OATH/HOTP keys, the query can be simplified or not.
If your token supports the 'Token Identifier', like Yubico Yubikeys, you can just
send one parameter, the generated string, and the Yubiserve Validation Server will
take care of looking for your key informations in the database.

If your token instead only generates the 6-8 digits, you will have to explicit
your publicID through another parameter.

So, you will have to query, via HTTP GET, the following address:
```
http://<server ip>:<server port>/wsapi/2.0/oathverify?otp=<your otp>&publicid=<token id>
ex.: http://192.168.0.1:8000/wsapi/2.0/oathverify?otp=80l944311056173483
ex.: http://192.168.0.1:8000/wsapi/2.0/oathverify?otp=173483&publicid=80l944311056
```
Both the examples works the same way: in the first case, the Token Identifier was
inside the generated OTP (like in Yubico Yubikey implementation), in the second case
an authentication through a LCD Token was made, so the Yubiserve needed to know who
the token belonged to, and the publicid parameter was added.

The response, like Yubico Yubikey queries, is the following:

```
otp=80l944311056173483
status=OK
t=2010-11-21T00:04:59
h=
```

The 'h' parameter is not set, because we didn't specified the API Key id. To use the
server signature, we will need to add the 'id' parameter, like in the following query:
```
ex.: http://192.168.1.2:8000/wsapi/2.0/oathverify?otp=80l944311056173483&id=1
ex.: http://192.168.0.1:8000/wsapi/2.0/oathverify?otp=173483&publicid=80l944311056&id=1
```

And this would be the the response:

```
otp=80l944311056173483
status=OK
t=2010-11-21T00:10:56
h=vYoG9Av8uG6OqVkmMFuANi4fyWw=
```