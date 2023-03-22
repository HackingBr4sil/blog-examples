# https://hackingbr4sil.wordpress.com/

import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_priv_pub_key():
    key = RSA.generate(2048)
    with open('private.pem', 'wb') as priv:
        priv.write(key.export_key())
    print('\n[+] Private key "private.pem" saved')

    with open('public.pem', 'wb') as pub:
        pub.write(key.publickey().export_key())
    print('[+] Public key "public.pem" saved')
    main()
    return


def encrypt(dest):
    with open(dest, 'rb') as enc_file:
        data_enc = enc_file.read()

    if os.path.isfile('public.pem'):
        public_rsa = RSA.import_key(open('public.pem').read())
        session_key = get_random_bytes(16)

        # criptografa a chave de sessao com chave publica RSA
        chips_rsa = PKCS1_OAEP.new(public_rsa)
        enc_session_key = chips_rsa.encrypt(session_key)

        # criptografa o arquivo com o algoritmo AES da chave de sessao
        chips_aes = AES.new(session_key, AES.MODE_EAX)
        chips_text, tag = chips_aes.encrypt_and_digest(data_enc)

        with open(f'{dest}.bin', 'wb') as file_out:
            for x in (enc_session_key, chips_aes.nonce, tag, chips_text):
                file_out.write(x)
        print(f'{dest} encrypted')
        os.remove(dest)
    else:
        print('\n[+] No public key for encryption. Generate Keys.')
        main()
        return


def decrypt(dest):
    if os.path.isfile("private.pem"):
        priv_key_rsa = RSA.import_key(open("private.pem").read())
        with open(dest, "rb") as file_in:
            enc_session_key, nonce, tag, chips_text = [file_in.read(x) for x in (priv_key_rsa.size_in_bytes(), 16, 16, -1)]

        #  descriptografia da chave de sessao com chave privada RSA
        chips_rsa = PKCS1_OAEP.new(priv_key_rsa)
        session_key = chips_rsa.decrypt(enc_session_key)

        # descriptografia de dados com algoritmo AES de chave de sessao
        chips_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = chips_aes.decrypt_and_verify(chips_text, tag)
        with open(dest[:-4], "wb") as file_out:
            file_out.write(data)
        print(f'{dest} decrypted')
        os.remove(dest)
    else:
        print('\n[+] There is no private key to decrypt.\nCopy the "private.pem" key to the folder with the script!')
        main()
        return


def user_change_scan_dir(user_change):
    if user_change == "1":
        generate_priv_pub_key()
    elif user_change == "2":
        dir_crypt = input('\n[+] Enter directory to encrypt: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] No such folder\n[+] Enter a directory to encrypt: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                encrypt(os.path.join(address, name))
        main()
        return
    elif user_change == "3":
        dir_crypt = input('\n[+] Enter directory for decryption: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] No such folder\n[+] Enter the decryption directory: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                decrypt(os.path.join(address, name))
        main()
        return
    elif user_change == "4":
        exit(0)
    else:
        main()
        return


def main():
    user_change = input('\n[+] Choose an action:\n\t[1] Generate public and private key;\n'
                        '\t[2] Encrypt files;\n\t[3] Decrypt files;\n\t[4] Exit\n\t>>> ')
    user_change_scan_dir(user_change)


if __name__ == "__main__":
    main()

