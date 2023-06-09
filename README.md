**AES Encryption and Decryption Tool**

*This is a Python program that provides an easy-to-use CLI for encrypting and decrypting text files using AES encryption. The program can be run from the command line and accepts the following arguments:*

- -ef or --encrypt-file - Encrypts the contents of a text file and outputs the encrypted message, encryption key and initialization vector.
- -df or --decrypt-file - Decrypts the contents of an encrypted text file and outputs the original plaintext.
- -e or --encrypt-text - Encrypts manually entered text and outputs the encrypted message, encryption key and initialization vector.
- -d or --decrypt-text - Decrypts manually entered encrypted text and outputs the original plaintext.
- -s or --show-encrypted - Displays the encrypted text.

*Requirements*
- pyperclip
- colorama
- termcolor

*Usage*
- To use this program, navigate to the directory containing the script in a terminal window and execute the following command:
python aes_tool.py [arguments]
Replace [arguments] with one of the options listed above.

! If running the program on Windows, it is recommended to use Command Prompt or PowerShell instead of Git Bash or other alternative terminals as they have been known to cause issues with the pyperclip library !

*Examples*
- Encrypting a file content:
python aes_tool.py -ef /path/to/file.txt

- Encrypting text from manual input:
python aes_tool.py -e "Hello, World!"

- Decrypting a file content:
python aes_tool.py -df /path/to/encrypted/file.txt

- Decrypting text:
python aes_tool.py -d "2c731eaa40cc1b3da3f80d1b55d05abe7e23c5a807af5aa8ead2eae614d74bbc"
