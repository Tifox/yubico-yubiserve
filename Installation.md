Installation is pretty simple, you just have to install few python packages:

Under Debian, you can run:
```
apt-get install python python-crypto python-openssl
```

If you want the sqlite support, you should run:
```
apt-get install python-sqlite
```
or, if you want the mysql support:
```
apt-get install python-mysqldb
```
Of course, you can have them both installed.

If you chosen the mysql support, you must create a database and create the
tables. The mysql dump is at src/dump.mysql. Then, configure your connection editing the file yubiserve.cfg.

You must have the certificate for ssl validation, so if you don't
already have a certificate you have to issue the following command to self-sign
one:
```
openssl req -new -x509 -keyout yubiserve.pem -out yubiserve.pem -days 365 -nodes
```

A good idea would be taking a look at yubiserve.cfg, to configure the validation server settings.

After installing the needed packages, you just need to add the keys and launch the server (or, if you prefer you can launch the server before adding the keys, it doesn't matter).