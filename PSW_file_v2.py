###################################################
###                                             ###
###         Encrypt-Decrypt 3 level depth       ###
###               Password Rewrite              ###
###                                             ###
###################################################
#
#  encrypt
#   python .\encrypt_decrypt.py -e -i .\Path\file -o .\encrypted_file -p Password123@ -k 4
#
#  decrypt
#   FOR DECRYPTION PASS I 
#   python .\encrypt_decrypt.py -d -i .\encrypted_file -p Password123@ -k 4
#
#  SAME k value, it is also like a part of password, default is 2
#  ccept multiple k, so there will are multiple pass ecnryption/decryption pass
#
#   python .\encrypt_decrypt.py -e -i .\Path\file -o .\encrypted_file -p Password123@ -k 4,5,6
#   python .\encrypt_decrypt.py -d -i .\encrypted_file -p Password123@ -k 4,5,6
#   

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from getpass import getpass
import shutil

from threading import Thread


class CryptoArc:
    ENCRYPT = 0
    DECRYPT = 1

    def AES256CBC(self, key_aes_cbc, plaintext):
        iv_aes_cbc = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_aes_cbc), modes.CBC(iv_aes_cbc), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext_aes_cbc = encryptor.update(padded_data) + encryptor.finalize()
        return (iv_aes_cbc,ciphertext_aes_cbc)
        
    def ChaCha20Poly1305(self, key_chacha, plaintext):
        nonce_chacha = os.urandom(12)
        chacha = ChaCha20Poly1305(key_chacha)
        ciphertext_chacha = chacha.encrypt(nonce_chacha, plaintext, None)
        return (nonce_chacha,ciphertext_chacha)
        
    def AES256GCM(self, key_aes_gcm, plaintext):
        nonce_aes_gcm = os.urandom(12)
        aesgcm = AESGCM(key_aes_gcm)
        ciphertext_aes_gcm = aesgcm.encrypt(nonce_aes_gcm, plaintext, None)
        return (nonce_aes_gcm,ciphertext_aes_gcm)

    def encrypt_file(self,input_file_path, output_file_path, password):
        # Read the plaintext file
        with open(input_file_path, 'rb') as f:
            plaintext = f.read()

        # Generate a random salt for key derivation
        salt = os.urandom(16)

        # Derive three 256-bit keys using Scrypt
        kdf = Scrypt(
            salt=salt,
            length=96,  # 32*3 bytes for three keys
            n=2**20,    # CPU/memory cost parameter
            r=8,
            p=1
        )
        keys = kdf.derive(password.encode())
        key_aes_cbc = keys[:32]
        key_chacha = keys[32:64]
        key_aes_gcm = keys[64:96]

        # Encrypt the original filename using AES-GCM
        original_filename = os.path.basename(input_file_path)
        filename_nonce = os.urandom(12)
        aesgcm_filename = AESGCM(key_aes_gcm)
        encrypted_filename = aesgcm_filename.encrypt(filename_nonce, original_filename.encode(), None)
        filename_length = len(encrypted_filename).to_bytes(4, 'big')  # 4-byte length prefix

        # Layer 1: AES-256-CBC Encryption
        nonce_l1, AESCBC_output = self.AES256CBC(key_aes_cbc, plaintext)
        layer1_output = nonce_l1+AESCBC_output
        
        
        # Layer 2: ChaCha20-Poly1305 Encryption
        nonce_l2, CHACHA_output = self.ChaCha20Poly1305(key_chacha, layer1_output)
        layer2_output = nonce_l2+CHACHA_output
        
        # Layer 3: AES-256-GCM Encryption
        nonce_l3, AESGCM_output = self.AES256GCM(key_aes_gcm, layer2_output)
        layer3_output = nonce_l3+AESGCM_output

        # Build final output with filename metadata
        final_output = (
            salt +
            filename_nonce +
            filename_length +
            encrypted_filename +
            layer3_output
        )

        # Write the encrypted data to the output file
        with open(output_file_path, 'wb') as f:
            f.write(final_output)

    def decrypt_file(self,input_file_path, output_file_path, password):
        # Read the encrypted file
        with open(input_file_path, 'rb') as f:
            encrypted_data = f.read()

        # Extract salt (first 16 bytes)
        salt = encrypted_data[:16]
        pos = 16  # Position after salt

        # Derive the keys using the salt and password
        kdf = Scrypt(
            salt=salt,
            length=96,
            n=2**20,
            r=8,
            p=1
        )
        keys = kdf.derive(password.encode())
        key_aes_cbc = keys[:32]
        key_chacha = keys[32:64]
        key_aes_gcm = keys[64:96]

        # Extract filename components
        filename_nonce = encrypted_data[pos:pos+12]
        pos += 12
        filename_length = int.from_bytes(encrypted_data[pos:pos+4], 'big')
        pos += 4
        encrypted_filename = encrypted_data[pos:pos+filename_length]
        pos += filename_length

        # Decrypt the filename
        aesgcm_filename = AESGCM(key_aes_gcm)
        original_filename = aesgcm_filename.decrypt(filename_nonce, encrypted_filename, None).decode()
        
        # Determine the output path
        if os.path.isdir(output_file_path) or original_filename.endswith("zippa"):
            # Use the original filename in the specified directory
            if not(os.path.isdir(output_file_path)):
                os.remove(output_file_path)
                os.makedirs(output_file_path, exist_ok=True)
                
            output_file_path = os.path.join(output_file_path, original_filename)
            
            if os.path.exists(output_file_path):
                output_file_path += "temp"
            
        else:
            if os.path.exists(output_file_path):
                output_file_path += "temp"
            

        # Extract main encrypted data components
        nonce_aes_gcm = encrypted_data[pos:pos+12]
        pos += 12
        ciphertext_aes_gcm = encrypted_data[pos:]

        # Layer 3: AES-256-GCM Decryption
        aesgcm = AESGCM(key_aes_gcm)
        layer2_output = aesgcm.decrypt(nonce_aes_gcm, ciphertext_aes_gcm, None)

        # Layer 2: ChaCha20-Poly1305 Decryption
        nonce_chacha = layer2_output[:12]
        ciphertext_chacha = layer2_output[12:]
        chacha = ChaCha20Poly1305(key_chacha)
        layer1_output = chacha.decrypt(nonce_chacha, ciphertext_chacha, None)

        # Layer 1: AES-256-CBC Decryption
        iv_aes_cbc = layer1_output[:16]
        ciphertext_aes_cbc = layer1_output[16:]
        cipher = Cipher(algorithms.AES(key_aes_cbc), modes.CBC(iv_aes_cbc), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext_aes_cbc) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Write the decrypted data to the output file
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        if output_file_path.endswith("zippa"):
            shutil.move(output_file_path,output_file_path[:-2])
            return (2,output_file_path[:-2])
        else:
            return (0,output_file_path)

    # The regenerate function and main block remain unchanged
    def regenerate(self, psw, n):
        p1 = psw
        for _ in range(n):
            p1 = "".join([str(ord(c)) for c in str(p1)]) 
            p1 = [chr(int(m)) for m in [p1[i:i+2] for i in range(len(p1)-1, 0, -2)]] 
        return "".join(p1)
    
    def __init__(self, mode, input_file, output_file="./", password="", k=[2], callback=None):   
        self.mode = mode
        self.input_file = input_file
        self.output_file = output_file
        self.password = password
        self.k = k
        self.callback = callback
        
    def run(self):
        
        final_output = self.output_file
        index = 0
        last_file = self.input_file
        file_name = self.input_file
        MULTI_PASS = len(self.k)>1
        
        while True:
            last_file = file_name
            knn = self.k[index]
            index +=1
            psw = "".join(self.regenerate(self.password, int(knn)))
            is_folder = False
            
            if os.path.isdir(self.input_file):
                is_folder = True
                out_folder = os.path.abspath(self.input_file)
                shutil.make_archive(out_folder.split("\\")[-1], 'zip', self.input_file)
                shutil.move(out_folder.split("\\")[-1]+".zip", out_folder.split("\\")[-1]+".zippa")
                self.input_file = out_folder.split("\\")[-1]+".zippa"
            
            if self.mode==self.ENCRYPT:
                self.encrypt_file(self.input_file, self.output_file, psw)
                print("Encryption completed successfully.",(str(index)+"/"+str(len(self.k)) if MULTI_PASS else ""))
                
                if is_folder:
                    os.remove(self.input_file)
                self.input_file = self.output_file
            elif self.mode==self.DECRYPT:
                try:
                    (ret,file_name) = self.decrypt_file(self.input_file, self.output_file, psw)
                    print("Decryption completed successfully.",(str(index)+"/"+str(len(self.k)) if MULTI_PASS else ""))
                    if ret == 2:
                        shutil.unpack_archive(file_name, file_name.replace(".zip",""), "zip")
                        os.remove(file_name)
                    self.input_file = file_name
                except InvalidTag:
                        print("Wrong password or corrupted file")
            
            if self.callback:
                self.callback(index,len(self.k))
                
            if len(self.k)<=index:
                break
                
        if os.path.exists(final_output) and not(final_output=="./") and "." in final_output:
            final_output = final_output.split(".")[:-1]+"_enc."+final_output.split(".")[-1]
        if self.input_file.endswith("temp"):
            t_nome = ".".join(self.input_file.split(".")[:-1])+"_enc."+self.input_file.split(".")[-1].replace("temp","")
            shutil.move(self.input_file, t_nome)
            self.input_file = t_nome
        if os.path.exists(self.input_file) and final_output!="./" and os.path.isfile(final_output):
            shutil.move(self.input_file, final_output)
        if os.path.exists(last_file) and self.mode==self.DECRYPT:
            os.remove(last_file)
            
        

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file using triple-layer encryption.')
    parser.add_argument("-e", "--encrypt", action='store_true', help="Encrypt mode")
    parser.add_argument("-d", "--decrypt", action='store_true', help="Decrypt mode")
    parser.add_argument('-i', '--input_file', help='Path to the input file')
    parser.add_argument('-o', '--output_file', default="./", help='Path to the output file')
    parser.add_argument('-p', "--password", default="", help="Password")
    parser.add_argument('-k', "--knn", default=2, help="number")
    args = parser.parse_args()
    
    
    if args.password == "":
        args.password = getpass("Enter password: ")
        
    if "," in args.knn:
        args.knn = args.knn.split(",")
        if args.decrypt:
            args.knn.reverse()
    CryptoArc(CryptoArc.ENCRYPT if args.encrypt else CryptoArc.DECRYPT, args.input_file, args.output_file, args.password, args.knn).run()
    