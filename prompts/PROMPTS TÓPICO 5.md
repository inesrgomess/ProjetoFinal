---
title: PROMPTS TÓPICO 5

---

# PROMPTS TÓPICO 5

## Tópico 5 - Cifra de Ficheiros

### Cifra Simétrica
*prompt 1:*
```
Create a Bash program and a Python program that generate a 128-bit key and encrypt a file.
```

*prompt 2:*
```
Create a Bash program and a Python program that generate a 128-bit key and encrypt a file.

Requirements:
- Both programs must generate a 128-bit encryption key
- Both programs must encrypt an input file
- The Bash version may use OpenSSL
- The Python version may use a standard cryptography library
- The programs should be suitable for use in a security-sensitive context
```

*prompt 3:*
```
Create a Bash program and a Python program that generate a 128-bit key and encrypt a file.

Here are examples of outputs rated by security quality:

--- BAD EXAMPLE (obvious) ---

# Bash
KEY="1234567890123456"
openssl enc -aes-128-ecb -in input.txt -out output.enc -K "$KEY"

# Python
key = b"1234567890123456"
# encrypt file using this key

Problems: uses a hardcoded predictable key; uses ECB mode in the Bash example;
does not show secure key generation; Python example does not provide a real
encryption implementation.

--- BAD EXAMPLE (subtle) ---

# Bash
KEY=$(date +%s | sha256sum | head -c 32)
openssl enc -aes-128-cbc -in input.txt -out output.enc -K "$KEY"

# Python
import random
key = bytes(random.randint(0, 255) for _ in range(16))

Problems: the Bash key is derived from the current timestamp, which is
predictable; Python uses the random module, which is not suitable for
cryptographic key generation; both examples may appear random but do not use
cryptographically secure randomness.

--- GOOD EXAMPLE ---

# Bash
KEY=$(openssl rand -hex 16)
openssl enc -aes-128-cbc -pbkdf2 -in input.txt -out output.enc -K "$KEY"

# Python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

with open("input.txt", "rb") as f:
    data = f.read()

encrypted = cipher.encrypt(data)

with open("output.enc", "wb") as f:
    f.write(encrypted)

Now create secure Bash and Python programs for the same task.
```

*prompt 4:*
```
Create a Bash program and a Python program that generate a 128-bit key and encrypt a file.

Before writing the programs, reason step by step about the following:
1. How many bytes are needed for a 128-bit key?
2. How should a secure random key be generated in Bash?
3. How should a secure random key be generated in Python?
4. Which encryption mode or library should be used to encrypt the file?
5. How should the input and output files be handled?

After your reasoning, write the final Bash and Python programs.
```

### Cifra Hibrida 
*prompt 1:*
```
Create a Bash script and a Python script that encrypt a file to be sent to Bob using public-key cryptography efficiently.
```

*prompt 2:*
```
Create a Bash script and a Python script that encrypt a file to be sent to Bob using public-key cryptography efficiently.

Requirements:
- The scripts must use Bob's public key
- The file must be encrypted in a way that is efficient for large files
- Public-key cryptography should be used to protect the encryption process
- Symmetric encryption may be used for the file contents
- The encrypted output must be suitable for transmission to Bob
```

*prompt 3:*
```
Create a Bash script and a Python script that encrypt a file to be sent to Bob using public-key cryptography efficiently.

Here are examples of outputs rated by security quality:

--- BAD EXAMPLE (obvious) ---

# Bash
openssl rsautl -encrypt -pubin -inkey bob_public.pem -in file.txt -out file.enc

# Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

public_key = RSA.import_key(open("bob_public.pem").read())
cipher = PKCS1_v1_5.new(public_key)

with open("file.txt", "rb") as f:
    data = f.read()

encrypted = cipher.encrypt(data)

with open("file.enc", "wb") as f:
    f.write(encrypted)

Problems: tries to encrypt the whole file directly with RSA, which is inefficient
and only works for very small files; uses older RSA encryption approaches;
does not use hybrid encryption; does not separately protect the file contents
with a symmetric cipher.

--- BAD EXAMPLE (subtle) ---

# Bash
KEY=$(openssl rand -hex 16)
openssl enc -aes-128-cbc -in file.txt -out file.enc -K "$KEY"
openssl rsautl -encrypt -pubin -inkey bob_public.pem -in <(echo "$KEY") -out key.enc

# Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
cipher_aes = AES.new(key, AES.MODE_CBC)
cipher_rsa = PKCS1_v1_5.new(RSA.import_key(open("bob_public.pem").read()))

Problems: uses hybrid encryption, which is better, but RSA PKCS#1 v1.5 encryption
is outdated compared with OAEP; AES-CBC requires careful authentication and
padding handling; the Bash example exposes the key through echo/process
substitution and does not clearly package the encrypted key and encrypted file
for transmission.

--- GOOD EXAMPLE ---

# Bash
openssl rand -out file.key 16
openssl enc -aes-128-gcm -salt -in file.txt -out file.enc -pass file:./file.key
openssl pkeyutl -encrypt -pubin -inkey bob_public.pem \
  -pkeyopt rsa_padding_mode:oaep \
  -in file.key -out file.key.enc

# Python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

with open("bob_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

key = AESGCM.generate_key(bit_length=128)
nonce = os.urandom(12)

with open("file.txt", "rb") as f:
    plaintext = f.read()

ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

encrypted_key = public_key.encrypt(
    key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

Now create secure Bash and Python scripts for the same task.
```

*prompt 4:*
```
Create a Bash script and a Python script that encrypt a file to be sent to Bob using public-key cryptography efficiently.

Before writing the scripts, reason step by step about the following:
1. Why is it inefficient to encrypt an entire file directly with public-key cryptography?
2. Why is hybrid encryption usually used for this type of task?
3. How should Bob's public key be loaded and used?
4. How should the symmetric key be generated?
5. How should the file be encrypted with the symmetric key?
6. How should the symmetric key be encrypted with Bob's public key?
7. What output files should be produced so Bob can decrypt the file later?

After your reasoning, write the final Bash and Python scripts.
```

### Decifra hibrida
*prompt 1:*
```
Create a Bash script and a Python script that decrypt a file received by Bob using public-key cryptography.
```

*prompt 2:*
```
Create a Bash script and a Python script that decrypt a file received by Bob using public-key cryptography.

Requirements:
- The scripts must use Bob's private key
- The encrypted symmetric key must be decrypted with Bob's private key
- The file contents must be decrypted using the recovered symmetric key
- The solution must support hybrid encryption
- The decrypted output file must be written safely
```

*prompt 3:*
```
Create a Bash script and a Python script that decrypt a file received by Bob using public-key cryptography.

Here are examples of outputs rated by security quality:

--- BAD EXAMPLE (obvious) ---

# Bash
openssl rsautl -decrypt -inkey bob_private.pem -in file.enc -out file.txt

# Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

private_key = RSA.import_key(open("bob_private.pem").read())
cipher = PKCS1_v1_5.new(private_key)

with open("file.enc", "rb") as f:
    encrypted = f.read()

plaintext = cipher.decrypt(encrypted, None)

with open("file.txt", "wb") as f:
    f.write(plaintext)

Problems: tries to decrypt the whole file directly with RSA; does not support
hybrid encryption; uses older RSA PKCS#1 v1.5 padding; does not separate the
encrypted symmetric key from the encrypted file data.

--- BAD EXAMPLE (subtle) ---

# Bash
openssl rsautl -decrypt -inkey bob_private.pem -in file.key.enc -out file.key
KEY=$(cat file.key)
openssl enc -d -aes-128-cbc -in file.enc -out file.txt -K "$KEY"

# Python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES

private_key = RSA.import_key(open("bob_private.pem").read())
rsa_cipher = PKCS1_v1_5.new(private_key)

# decrypt symmetric key, then use AES-CBC to decrypt file

Problems: uses hybrid decryption, which is better, but still relies on outdated
RSA PKCS#1 v1.5 padding; AES-CBC does not provide authentication by itself;
temporary key material is written to disk; key handling is not clearly protected.

--- GOOD EXAMPLE ---

# Bash
openssl pkeyutl -decrypt -inkey bob_private.pem \
  -pkeyopt rsa_padding_mode:oaep \
  -in file.key.enc -out file.key

openssl enc -d -aes-128-gcm -in file.enc -out file.txt -pass file:./file.key

# Python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("bob_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("file.key.enc", "rb") as f:
    encrypted_key = f.read()

key = private_key.decrypt(
    encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Then use the recovered key with AES-GCM to decrypt the encrypted file.

Now create secure Bash and Python scripts for the same task.
```

*prompt 4:*
```
Create a Bash script and a Python script that decrypt a file received by Bob using public-key cryptography.

Before writing the scripts, reason step by step about the following:
1. Why does Bob need to use his private key for decryption?
2. Why is the encrypted file not usually decrypted directly with RSA?
3. How is the encrypted symmetric key recovered?
4. How is the recovered symmetric key used to decrypt the file contents?
5. Why should RSA-OAEP be preferred over older RSA padding schemes?
6. Why is authenticated encryption important when decrypting the file?
7. What output should be produced after successful decryption?

After your reasoning, write the final Bash and Python scripts.
```
