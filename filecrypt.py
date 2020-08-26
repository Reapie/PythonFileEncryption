#!/usr/bin/env python
import click
import os
import base64
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key(password : str):
    password = password.encode()

    salt = b"[R8b\x7f\xd2\xd1s\x975\x17\xd1\xd7\xf3\xdd\xd2"

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA512(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )

    return base64.urlsafe_b64encode(kdf.derive(password))

@click.group()
def cli():
    pass

@cli.command()
@click.argument("input_file")
@click.argument("password")
@click.option("--delete", is_flag = True)
def encrypt(input_file : str, password : str, delete : bool):
    output_file = input_file + ".cry"

    with open(input_file, "rb") as f:
        data = f.read()

    print(f"Encrypting {os.path.abspath(input_file)}")

    fernet = Fernet(get_key(password))
    encrypted = fernet.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted)

    if delete:
        os.remove(input_file)
        print("Deleted Input File")

    print("Done")


@cli.command()
@click.argument("input_file")
@click.argument("password")
@click.option("--delete", is_flag = True)
def decrypt(input_file : str, password : str, delete : bool):
    if (input_file.endswith(".cry")):
        output_file = input_file[:-4]

    with open(input_file, 'rb') as f:
        data = f.read()

    print(f"Decrypting {os.path.abspath(input_file)}")

    fernet = Fernet(get_key(password))
    encrypted = fernet.decrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    if delete:
        os.remove(input_file)
        print("Deleted Input File")

    print("Done")


cli.add_command(encrypt)
cli.add_command(decrypt)

if __name__ == '__main__':
    print("Reapie's File Encryption / Decryption Tool\n")
    cli()

    

