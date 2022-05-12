#!/usr/bin/env python3
import argparse
import csv
import re
import base64
import sys
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# DECRYPTION ###################################################################
def decrypt(mode, data, password):
    if (mode == 'CBC'):
        return cbc_decrypt(data, password)
    if (mode == 'GCM'):
        return gcm_decrypt(data, password)
    raise ValueError(f'unkown mode {mode}')

def gcm_decrypt(data, password):
    salt =       data[:16]
    nonce =      data[16:32]
    ciphertext = data[32:-16]
    tag =        data[-16:]
    # TODO: get these values from the config file
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)   # default values
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(salt)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print('MAC tag not valid, this means the master password is wrong or the crypto values aren\'t default')
        exit(1)
    return plaintext

def cbc_decrypt(data, password):
    iv = data[:16]
    ciphertext = data[16:]
    key = hashlib.md5(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# UTILITY FUNCTIONS ############################################################
def print_output(name, hostname, username, password):
    if args.csv :
        csv_out.writerow((name, hostname, username, password))
    else:
        print('Name: {}\nHostname: {}\nUsername: {}\nPassword: {}\n'.format(name, hostname, username, password))

def get_field(name, string):
    """ extract value of field <name> from string"""
    expr= r' '+name+'="([^"]*)"'
    matches=re.findall(expr, string)

    if matches:
        return matches[0]
    else:
        return None

# MAIN #########################################################################
parser = argparse.ArgumentParser(description = 'Decrypt mRemoteNG configuration files')
parser.add_argument('config_file', type=str, help='mRemoteNG XML configuration file')
parser.add_argument('-p', '--password', type=str, default='mR3m', help='Optional decryption password')
parser.add_argument('--csv',    default=False, action='store_true', help ='Output CSV format')
parser.add_argument('--check',  default=False, action='store_true', help='Check decryption password')
parser.add_argument('--all',    default=False, action='store_true', help='Dump all entries. By default only entries with password are dumped.')
args = parser.parse_args()

with open(args.config_file, 'r') as f:
    conf = f.read()

mode = get_field('BlockCipherMode', conf)
if not mode:
    mode = 'CBC'    #  <1.75 key is    md5(password) and encryption is CBC
elif mode != 'GCM': # >=1.75 key is PBKDF2(password) and encryption is GCM
    print('Unknown mode {}, implement it yourself or open a ticket'.format(mode))
    sys.exit(1)

if args.check:
    # Check if we can decrypt the value in "Protected" field
    # mRemoteNG 1.77.3-dev/mRemoteNG/Config/Serializers/ConnectionSerializers/Xml/XmlRootNodeSerializer.cs
    # specifies this field will contain "ThisIsProtected" or "ThisIsNotProtected". Not sure about previous versions.
    # see also mRemoteNG/Config/Serializers/XmlConnectionsDecryptor.cs
    cypher=base64.b64decode(get_field('Protected', conf))
    clear=decrypt(mode, cypher, args.password.encode())
    print("If the following is readable, then you can decrypt the file with the given password")
    print(clear)
    sys.exit(0)

# Extract and decrypt file data if FullFileEncryption is true
full_encryption = get_field('FullFileEncryption', conf)
if (full_encryption  == 'true'):
    cypher=base64.b64decode(re.findall('<.*>(.+)</mrng:Connections>', conf)[0]) 
    conf=decrypt(mode, cypher, args.password.encode())

nodes = re.findall('<Node .+?>', conf)
if not nodes:
    print(f"Could not find <Node > element in file '{args.config_file}'")
    sys.exit(2)

if args.csv :
    csv_out = csv.writer(sys.stdout, dialect='unix', quoting=csv.QUOTE_MINIMAL)
    csv_out.writerow(('Name', 'Hostname', 'Username', 'Password'))

for node in nodes:
    name =     get_field('Name', node)
    username = get_field('Username', node)
    hostname = get_field('Hostname', node)
    data = base64.b64decode(get_field('Password', node))
    password=""
    if data != b'':
        password=decrypt(mode, data, args.password.encode())
    
    if not password and not args.all:
        continue

    print_output(name, hostname, username, password)
