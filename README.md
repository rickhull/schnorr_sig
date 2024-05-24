# Schnorr Signatures

This is a simple, minimal library written in Ruby for the purpose of
calculating and verifying so-called
[Schnorr signatures](https://en.wikipedia.org/wiki/Schnorr_signature),
based on elliptic curve cryptography.  This cryptographic method was
[patented by Claus P. Schnorr in 1989](https://patents.google.com/patent/US4995082),
and the patent expired in 2010, and by 2021, it was adopted and popularized
by the [Bitcoin](https://en.wikipedia.org/wiki/Bitcoin) project.

This work is based on [BIP340](https://bips.xyz/340), one of the many
[Bitcoin Improvement Proposals](https://bips.xyz/), which are open documents
and specifications similar to
[IETF RFCs](https://en.wikipedia.org/wiki/Request_for_Comments).

BIP340 specifies elliptic curve `secp256k1` for use with Schnorr signatures.

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

msg = 'hello world'

# generate secret key and public key
sk, pk = Schnorr.keypair

# sign a message; exception raised on failure
sig = Schnorr.sign(sk, msg)

# the signature has already been verified, but let's check
Schnorr.verify(pk, msg, sig)  # => true
```
