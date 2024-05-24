# Schnorr Signatures

This is a simple, minimal library written in Ruby for the purpose of
calculating and verifying so-called
[Schnorr signatures](https://en.wikipedia.org/wiki/Schnorr_signature),
based on elliptic curve cryptography.

## Install

Install locally:

```
$ gem install schnorr_sig
```

Or add to your project `Gemfile`:

```
gem 'schnorr_sig'
```

## Usage

```
require 'schnorr_sig'

# generate secret key and public key
sk, pk = Schnorr.keypair

# sign a message, exception raised on failure
sig = Schnorr.sign(sk, 'hello world')

# the signature has already been verified, but let's check
Schnorr.verify(pk, m, sig)  # => true
```
