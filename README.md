# python_CryptoArc
simple three level encrypt-decrypt python project with password rewriting

## GUI interface
Launch the PSW_interface.py

## Console
```
  encrypt
   python .\encrypt_decrypt.py -e -i .\Path\file -o .\encrypted_file -p Password123@ -k 4

  decrypt
   python .\encrypt_decrypt.py -d -i .\encrypted_file -p Password123@ -k 4
   Don't use output name, it is encrypted in the file

  KEEP the same k being essential to rewrite the key
  Accept multiple k, so there will are multiple pass ecnryption/decryption pass

   python .\encrypt_decrypt.py -e -i .\Path\file -o .\encrypted_file -p Password123@ -k 4,5,6
   python .\encrypt_decrypt.py -d -i .\encrypted_file -p Password123@ -k 4,5,6
```
