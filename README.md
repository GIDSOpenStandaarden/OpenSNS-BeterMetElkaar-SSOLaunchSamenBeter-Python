# OpenSNS-BeterMetElkaar-SSOLaunchSamenBeter-Python

SNS Launch protocol code example in Python.

This repository provides Python code examples on how to implement the [SNS Launch protocol](https://github.com/GidsOpenStandaarden/OpenSNS-BeterMetElkaar-SSOLaunchSamenBeter-Protocol).

# Example 1. Generate a SNS Launch token with an RSA key

```python
import jwt
import time
from uuid import uuid4
 
 
def main():
    # The public key as provided by appendix A.
    private_key = '...'
    # Format as PEM key
    public_key_formatted = f'-----BEGIN PRIVATE KEY-----\n' \
        f'{private_key}' \
        f'\n-----END PRIVATE KEY-----'
 
    # Time function
    payload = {}
    payload['sub'] = 'urn:sns:user:issuer.nl:123456'
    payload['aud'] = 'audience.nl'
    payload['iss'] = 'issuer.nl'
    payload['resource_id'] = 'dagstructuur'
    payload['first_name'] = 'Klaas'
    payload['middle_name'] = 'de'
    payload['last_name'] = 'Vries'
    payload['email'] = 'klaas@devries.nl'
    payload['iat'] = time.time()
    payload['exp'] = time.time() + (5 * 60 * 1000)
    payload['jti'] = str(uuid4())
 
    jwt_encode = jwt.encode(payload, public_key_formatted, algorithm='RS256').decode('utf8')
    print(jwt_encode)
 
 
if __name__ == '__main__':
    main()
```

# Example 2. Validate a SNS Launch message

```python
import sys
import jwt
 
 
def main(jwt_token):
    # The public key as provided by appendix A.
    public_key = '...'
    # Format as PEM key
    public_key_formatted = f'-----BEGIN PUBLIC KEY-----\n' \
        f'{public_key}' \
        f'\n-----END PUBLIC KEY-----'
    # Use the JWT decode, make sure to set the audience
    jwt_decode = jwt.decode(jwt_token, public_key_formatted,
                            audience="audience.nl")
    user_id = jwt_decode['sub']
    email = jwt_decode['email']
    first_name = jwt_decode['first_name']
    middle_name = jwt_decode['middle_name']
    last_name = jwt_decode['last_name']
    issuer = jwt_decode['iss']
    unique_message_id = jwt_decode['jti']
    treatment_id = jwt_decode['resource_id']
    print(f'User {first_name} {middle_name} {last_name} with email {email} '
          f'from {issuer} wants to launch treatment {treatment_id} '
          f'with launch id {unique_message_id}')
```

# Example 3. Generate a RSA key pair

```python
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
 
 
def main():
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2024
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print('Public key {}'.format(public_key))
    print('Private key {}'.format(private_key))
 
 
if __name__ == '__main__':
    main()
```

# Example 4. Generate a EC key pair

```python
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec
 
 
def main():
    key = ec.generate_private_key(
        curve=ec.SECP256K1,
        backend=crypto_default_backend()
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print('Public key {}'.format(public_key))
    print('Private key {}'.format(private_key))
 
 
if __name__ == '__main__':
    main()
```

# requirements.txt

```python
pyjwt==1.7.1
cryptography==2.5
```

# Common pitfalls
PyJWT key encoding.

A common problem with PyJWT is the encoding of the public / private key with the PyJWT library. It requires the PEM formatting:

```python
-----BEGIN PUBLIC KEY-----
 
...
 
-----END PUBLIC KEY-----
```
