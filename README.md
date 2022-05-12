Decrypt mRemoteNG passwords
===========================

Decrypt mRemoteNG configuration files, old and new format.

More info [here](https://www.errno.fr/mRemoteNG).

Usage
-----
```
usage: mremoteng_decrypt.py [-h] [-p PASSWORD] config_file

Decrypt mRemoteNG configuration files

positional arguments:
  config_file                       mRemoteNG XML configuration file

optional arguments:
  -p PASSWORD, --password PASSWORD  Optional decryption password
  --csv                 Output CSV format
  --check               Check decryption password
  --all                 Dump all entries. By default only entries with
                        password are dumped.

```

Example:
```
mremoteng_decrypt.py ./mRemoteNG-1.70/confCons.xml
```
