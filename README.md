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

## Elliptic Curves

Note that [elliptic curves](https://en.wikipedia.org/wiki/Elliptic_curve)
are not ellipses, but can instead be described by cubic equations of
the form: `y^2 = x^3 + ax + b` where `a` and `b` are the parameters of the
resulting curve.  All points (x, y) which satisfy a given parameterized
equation provide the exact definition of an elliptic curve.

`secp256k1` uses `a = 0` and `b = 7`, so `y^2 = x^3 + 7`

Elliptic curves have an algebraic structure which involve mathematical
structures like Groups and Fields, and prime numbers are useful.  I won't
elaborate further here, as I am still learning in this area.

## Generator Point

Every elliptic curve has an *infinity point*, and one step away from the
infinity point is a so-called *generator point*, `G`.  Add `G` to the infinity
point; the result is `G`.  Add `G` again, and the result is `2G`.  Where `N`
is the *order* of the curve, `NG` returns to the infinity point.

You can multiply `G` by any integer < `N` to get a corresponding point on
the curve. So `G` is a point, a pair of large integers, `(x, y)`.  `G` can
be compressed to just the x-value, as the y-value can be derived from the
x-value with a little bit of algebra: `y = sign(x) * sqrt(x^3 + ax + b)`.

## Bignums

We can conjure into existence a gigantic 32-byte integer.  Note that until
recently, most consumer CPUs could only handle 32-bit integers.  A 32-byte
integer is 8x larger than common hardware integers, so math on large integers
must be done in software.

In Ruby, you can get a 32-byte value with: `Random.bytes(32)`, which will
return a 32-byte binary string.  There are several ways to convert this to
an integer value, which in Ruby is called a **Bignum** when it exceeds
the highest value for a **Fixnum**, which corresponds to a hardware integer.

Takeaway: *Fixnums are fast; Bignums are slow*

## Keypairs

Let's conjure into existence a gigantic 32-byte integer:

```
sk = Random.bytes(32)     # a binary string, length 32
hex = [str].pack('H*')    # convert to a hex string like: "199ace9bc1 ..."
bignum = hex.to_i(16)     # convert hex to integer, possibly a bignum
```

`bignum` is the integer value of our private key, randomly generated.
We can multiply it by `G` to get a corresponding point on the elliptic curve,
`P`.  `P.x` is now our public key, the x-value of a point on the curve.

Keep in mind:

* For any given secret key (32 byte value), a public key is easily generated
* For any given x-value on the curve, the y-value is easily generated
* For some curves, there can be two different y-values for an x-value

# Implementation

There are two independent implementations, one aiming for as pure Ruby as
possible, the other aiming for speed and correctness, relying on the
battle-tested [sep256k1 library](https://github.com/bitcoin-core/secp256k1)
provided by the Bitcoin project.

## Ruby Implementation

This is the default implementation and the only implementation for which
this gem specifies its dependencies:
the [ecdsa_ext](https://github.com/azuchi/ruby_ecdsa_ext) gem, which depends
on the [ecdsa](https://github.com/DavidEGrayson/ruby_ecdsa/) gem,
which implements the Elliptic Curve Digital Signature Algorithm (ECDSA)
almost entirely in pure Ruby.

**ecdsa_ext** provides computational efficiency for points on elliptic
curves by using projective (Jacobian) rather than affine coordinates.
Very little of the code in this library relies on these gems -- mainly
for elliptical curve computations and the `secp256k1` curve definition.

Most of the code in this implementaion is based directly on the pseudocode
from [BIP340](https://bips.xyz/340).  i.e. A top-to-bottom implementation
of most of the spec.  Enough to generate keypairs, signatures, and perform
signature verification.  Extra care was taken to make the Ruby code match
the pseudocode as close as feasible.  The pseudocode is commented
[inline](lib/schnorr_sig.rb#L58).

A lot of care was taken to keep conversions and checks to a minimum.  The
functions are very strict about what they accept and attempt to be as fast
as possible, while remaining expressive.  This implementation should
outperform [bip-schnorrb](https://github.com/chaintope/bip-schnorrrb)
in speed, simplicity, and expressiveness.

## Fast Implementation

This implementation depends on the
[rbsecp256k1](https://github.com/etscrivner/rbsecp256k1) gem, which is a
C extension that wraps the
[secp256k1](https://github.com/bitcoin-core/secp256k1) library, also known
as **libsecp256k1**.  There is much less code here, but the `SchnorrSig`
module functions perform some input checking and match the function
signatures from the Ruby implementation.  There are many advantages to
using this implementation over the Ruby implementation, aside from
efficiency, mostly having to with resistance to timing and side-channel
attacks.

The downside of using this implementation is a more difficult and involved
install process, along with a certain level of inscrutability.

### Temporary Restriction

Currently, **rbsecp256k1** restricts messages to exactly 32 bytes, which
was part of the BIPS340 spec until April 2023, when the restriction was lifted.

See https://github.com/etscrivner/rbsecp256k1/issues/80

# Usage

This library is provided as a RubyGem.  It has a single dependency on
[ecdsa_ext](https://github.com/azuchi/ruby_ecdsa_ext), with a
corresponding transitive dependency on
[ecdsa](https://github.com/DavidEGrayson/ruby_ecdsa/).

## Install

Install locally:

```
$ gem install schnorr_sig
```

Or add to your project `Gemfile`:

```
gem 'schnorr_sig'
```

By default, only the dependencies for the Ruby implementation will be
installed: **ecdsa_ext** gem and its dependencies.

### Fast Implementation

After installing the **schnorr_sig** gem, then install **rbsecp256k1**.
Here's how I did it on NixOS:

```
nix-shell -p secp256k1 autoconf automake libtool
gem install rbsecp256k1 -- --with-system-libraries
```

## Example

```ruby
require 'schnorr_sig'

msg = 'hello world'

# generate secret key and public key
sk, pk = SchnorrSig.keypair

# sign a message; exception raised on failure
sig = SchnorrSig.sign(sk, msg)

# the signature has already been verified, but let's check
SchnorrSig.verify?(pk, msg, sig)  # => true
```

### Fast Implementation

```ruby
require 'schnorr_sig/fast' # not 'schnorr_sig'

# everything else as above ...
```
