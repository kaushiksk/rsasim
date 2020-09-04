![Python package](https://github.com/kaushiksk/rsasim/workflows/Python%20package/badge.svg?branch=master)

rsasim
=========

A pure python implementation of rsa, for fun and experimenting.
Please note that to be used in production a lot of constraints have to be imposed on rsa and that the given module only serves as a proof of concept and should not be used in production.

## Demo
 - [RSA Blinding attack using the rsasim module](https://gist.github.com/kaushiksk/57a74e7160ee0b8d3bfce1c80bbfb134)
## Installation

`$ git clone https://github.com/kaushiksk/rsasim && cd rsasim`

`$ pip install . --user`

or

`$ python setup.py install --user`

For python3 install, run the second command with pip3 or the last command with python3.

## Components

In addition to the `rsasim` package, two command line scripts `isprime` and
`genprime` are also installed.

## Usage

### rsasim

```python
>>> from rsasim import RSA
>>> A = RSA()  # Alice
>>> B = RSA()  # Bob
>>> E = RSA()  # Eve
```

Alice wants to talk to Bob so she will encrypt her message using Bob's public key
```python
>>> ciphertext_B = A.encrypt("Hello Bob", B.public_key)
>>> B.decrypt(ciphertext_B) 
'Hello Bob'
```

If Eve tries to decrypt this
```python
>>> E.decrypt(ciphertext_B)
'\x12\x0eA\x8c\xc5\x1f\xa1\x05\xfe\x80Q\x1e\x1b|\xbb\xb8\xe9\xa6\x84\xc1\xda\x8b:XC\xed\x91\xb8\x12q\x11\xd9'
```

The above result may vary as the keys are randomly generated each time.

The API remains the same for numbers
```python
>>> ciphertext_E = A.encrypt(123456789, E.public_key)
>>> E.decrypt(ciphertext_E)
123456789L
>>> B.decrypt(ciphertext_E)
4081228201739686282145927510867027940582326297585236661320804597753581131993L
```

You can view anyone's public key but cannot alter it directly.
```python
>>> A.public_key = (2,3)
Exception: You are not allowed to alter generated keys
>> A.public_key
(56618467399119298776135038168667997056624964942029346840873882494861567586229L, 92020774583088837673591629484044516416427751099585188055672485398962861161269L)
```

Digital signatures can be achieved in a similar manner. Alice signs a string or number with her private key.
```python
>>> sign_a = A.sign("Alice's Signature")
```

Bob or Eve can verify this. It can only be verified with Alice's public key.
```python
>>> B.verify(sign_a, A.public_key)
"Alice's Signature"
>>> E.verify(sign_a, A.public_key)
"Alice's Signature"
>>> B.verify(sign_a, E.public_key)
'\x1cv\x04@j\xf2\x04\x83!\xab\x01uN\xd8\x02Y\xc8\xd43\rD\x59c9I@c\x92\x0c)/\xe2\x9c0'
```

The `process_string()` and `recover_string()` `@classmethod`s are used to convert between byte strings and long integers. It is a slightly simplified version of the code [here](https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py)

```python
>>> RSA.process_string("Hi Bob")
79616349990754
>> RSA.process_string("Hi Bob what's up?")
24640066858828187311071388516817835487295L
>>> RSA.recover_string(79616349990754)
'Hi Bob'
```
### isprime

Check whether a number is prime or not from the command line. The script internally uses the Miller Rabin Primality test.

```bash
$ isprime 13
True
$ isprime 213
False
```

### genprime

Generate a random prime number. A 100 bit random prime number is generated by default. You can generate a fixed bit length prime using the --bits argument.

```bash
$ genprime
213209838925001955916657635071
$ genprime --bits 50
419883489883873
$ genprime -h
```

## Development Notes

For development notes and commit history check [this repo](https://www.github.com/kaushiksk/rsa-from-scratch)