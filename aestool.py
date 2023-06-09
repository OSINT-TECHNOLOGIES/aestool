import argparse
import os
import sys
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

try:
    import pyperclip
    from colorama import Fore, Style, Back
    from termcolor import colored
except ImportError:
    print(Fore.RED + "Please install pyperclip, colorama and termcolor libraries before running this program")
    sys.exit(1)


def read_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            return content.decode('utf-8')
    except FileNotFoundError:
        output_message(Fore.RED + "File not found!" + Style.RESET_ALL)
        sys.exit(1)



def encrypt_text(key, iv, plaintext):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return binascii.hexlify(ciphertext).decode()


def decrypt_text(key, iv, ciphertext):
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        padded_plaintext = decryptor.update(binascii.unhexlify(ciphertext)) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  # specify padding scheme
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
    except ValueError as e:
        output_message(Fore.RED + f"Decryption failed: {str(e)}" + Style.RESET_ALL)
        sys.exit(1)


def copy_to_clipboard(ciphertext, key, iv):
    formatted_text = "Ciphertext: {}\nEncryption key: {}\nInitialization vector: {}".format(ciphertext, key, iv)
    pyperclip.copy(formatted_text)
    print(Fore.GREEN + "Ciphertext, encryption key and initialization vector were copied to clipboard!" + Style.RESET_ALL)


def output_message(message, color=Fore.WHITE):
    print(color + message + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description= (colored("AES ENCRYPTION AND DECRYPTION TOOL", 'red', 'on_green')))
    parser.add_argument("-ef", "--encrypt-file", metavar="FILEPATH", help="Encrypt text from file")
    parser.add_argument("-df", "--decrypt-file", metavar="FILEPATH", help="Decrypt text from file")
    parser.add_argument("-e", "--encrypt-text", help="Encrypt text from manual input")
    parser.add_argument("-d", "--decrypt-text", help="Decrypt text from manual input")
    parser.add_argument("-s", "--show-encrypted", action="store_true", help="Display the encrypted text")

    args = parser.parse_args()

    if not any([args.encrypt_file, args.decrypt_file, args.encrypt_text, args.decrypt_text]):
        parser.print_help()
        sys.exit(1)

    if args.encrypt_file:
        plaintext = read_file(args.encrypt_file)
        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = encrypt_text(key, iv, plaintext)

        output_message("Ciphertext: " + ciphertext, color=Fore.GREEN)
        output_message("Encryption Key: " + binascii.hexlify(key).decode(), color=Fore.YELLOW)
        output_message("Initialization Vector: " + binascii.hexlify(iv).decode(), color=Fore.YELLOW)

        if args.show_encrypted:
            output_message("\nEncrypted text:\n" + ciphertext, color=Fore.GREEN)

        copy_to_clipboard(ciphertext, binascii.hexlify(key).decode(), binascii.hexlify(iv).decode())

    elif args.encrypt_text:
        key = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = encrypt_text(key, iv, args.encrypt_text)

        output_message("Ciphertext: " + ciphertext, color=Fore.GREEN)
        output_message("Encryption Key: " + binascii.hexlify(key).decode(), color=Fore.YELLOW)
        output_message("Initialization Vector: " + binascii.hexlify(iv).decode(), color=Fore.YELLOW)

        if args.show_encrypted:
            output_message("\nEncrypted text:\n" + ciphertext, color=Fore.GREEN)

        copy_to_clipboard(ciphertext, binascii.hexlify(key).decode(), binascii.hexlify(iv).decode())

    elif args.decrypt_file:
        ciphertext = read_file(args.decrypt_file)
        key = input("Enter encryption key: ")
        iv = input("Enter initialization vector: ")
        plaintext = decrypt_text(binascii.unhexlify(key), binascii.unhexlify(iv), ciphertext)
        output_message("Plaintext: " + plaintext, color=Fore.GREEN)

    elif args.decrypt_text:
        key = input("Enter encryption key: ")
        iv = input("Enter initialization vector: ")
        plaintext = decrypt_text(binascii.unhexlify(key), binascii.unhexlify(iv), args.decrypt_text)
        output_message("Plaintext: " + plaintext, color=Fore.GREEN)

    else:
        parser.print_help()
        sys.exit(1)



if __name__ == "__main__":
    main()