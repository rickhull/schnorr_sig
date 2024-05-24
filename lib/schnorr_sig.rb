require 'ecdsa_ext'
autoload :SecureRandom, 'securerandom'

# This implementation is based on the spec: https://bips.xyz/340
module Schnorr
  class BoundsError < RuntimeError; end
  class SizeError < RuntimeError; end
  class TypeError < RuntimeError; end
  class SanityCheck < RuntimeError; end
  class EncodingError < RuntimeError; end
  class VerifyFail < RuntimeError; end

  GROUP = ECDSA::Group::Secp256k1
  P = GROUP.field.prime
  N = GROUP.order

  FORMAT_IOS = ECDSA::Format::IntegerOctetString
  FORMAT_POS = ECDSA::Format::PointOctetString
  FORMAT_FEOS = ECDSA::Format::FieldElementOctetString

  # likely returns a Bignum, larger than a 64-bit hardware integer
  def self.bin2big(str)
    bin2hex(str).to_i(16)
  end

  # convert a giant integer to a binary string
  def self.big2bin(bignum)
    FORMAT_IOS.encode(bignum, GROUP.byte_length)
  end

  # convert a binary string to a lowercase hex string
  def self.bin2hex(str)
    str.unpack1('H*')
  end

  # convert a hex string to a binary string
  def self.hex2bin(hex)
    [hex].pack('H*')
  end

  # val (dot) G
  def self.dot_group(val)
    (GROUP.generator.to_jacobian * val).to_affine
  end

  # returns even_val or N - even_val
  def self.select_even_y(point, even_val)
    point.y.even? ? even_val : N - even_val
  end

  # provide an int(x) function that matches BIP340
  def self.int(val)
    bin2big(val)
  end

  # return a binary string
  def self.bytes(val)
    case val
    when Integer
      # BIP340: The function bytes(x), where x is an integer,
      # returns the 32-byte encoding of x, most significant byte first.
      big2bin(val)
    when ECDSA::Point
      # BIP340: The function bytes(P), where P is a point, returns bytes(x(P)).
      val.infinity? ? ("\x00" * 32).b : FORMAT_FEOS.encode(val.x, GROUP.field)
    else
      raise(SanityCheck, val.inspect)
    end
  end

  # Input
  #   The secret key, sk:       32 bytes binary
  #   The message, m:           binary
  #   Auxiliary random data, a: 32 bytes binary
  # Note: this deals with N (the order) and not P (the prime)
  def self.sign(sk, m, a = Random.bytes(32))
    raise(TypeError, "sk: string") unless sk.is_a? String
    raise(SizeError, "sk: 32 bytes") unless sk.bytesize == 32
    raise(EncodingError, "sk: binary") unless sk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String
    raise(TypeError, "a: string") unless a.is_a? String
    raise(SizeError, "a: 32 bytes") unless a.bytesize == 32
    raise(EncodingError, "a: binary") unless a.encoding == Encoding::BINARY

    # BIP340: Let d' = int(sk)
    d0 = int(sk)

    # BIP340: Fail if d' = 0 or d' >= n
    raise(BoundsError, "sk") if d0 <= 0 or d0 >= N

    # BIP340: Let P = d' . G
    p = dot_group(d0) # this is a point on the elliptic curve
    bytes_p = bytes(p)

    # BIP340: Let d = d' if has_even_y(P), otherwise let d = n - d'
    d = select_even_y(p, d0)

    # BIP340: Let t be the bytewise xor of bytes(d) and hash[BIP0340/aux](a)
    t = d ^ int(tagged_hash('BIP0340/aux', a))

    # BIP340: Let rand = hash[BIP0340/nonce](t || bytes(P) || m)
    nonce = tagged_hash('BIP0340/nonce', bytes(t) + bytes_p + m)

    # BIP340: Let k' = int(rand) mod n
    k0 = int(nonce) % N

    # BIP340: Fail if k' = 0
    raise(BoundsError, "k0") if k0 == 0

    # BIP340: Let R = k' . G
    r = dot_group(k0) # this is a point on the elliptic curve
    bytes_r = bytes(r)

    # BIP340: Let k = k' if has_even_y(R), otherwise let k = n - k'
    k = select_even_y(r, k0)

    # BIP340:
    #   Let e = int(hash[BIP0340/challenge](bytes(R) || bytes(P) || m)) mod n
    e = int(tagged_hash('BIP0340/challenge', bytes_r + bytes_p + m)) % N

    # BIP340: Let sig = bytes(R) || bytes((k + ed) mod n)
    sig = bytes_r + bytes((k + e * d) % N)

    # BIP340: Fail unless Verify(bytes(P), m, sig)
    raise(VerifyFail) unless verify(bytes_p, m, sig)

    # BIP340: Return the signature sig
    sig
  end

  # see https://bips.xyz/340#design (Tagged hashes)
  def self.tagged_hash(tag, msg)
    raise(TypeError, "tag: string") unless tag.is_a? String
    raise(EncodingError, "tag: utf-8") unless tag.encoding == Encoding::UTF_8
    raise(TypeError, "msg: string") unless msg.is_a? String

    # BIP340: The function hash[name](x) where x is a byte array
    #         returns the 32-byte hash
    #         SHA256(SHA256(tag) || SHA256(tag) || x)
    #         where tag is the UTF-8 encoding of name.
    tag_hash = Digest::SHA256.digest(tag)
    Digest::SHA256.digest(tag_hash + tag_hash + msg)
  end

  # Input
  #   The public key, pk: 32 bytes binary
  #   The message, m: binary
  #   A signature, sig: 64 bytes binary
  def self.verify(pk, m, sig)
    raise(TypeError, "pk: string") unless pk.is_a? String
    raise(SizeError, "pk: 32 bytes") unless pk.bytesize == 32
    raise(EncodingError, "pk: binary") unless pk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String
    raise(TypeError, "sig: string") unless sig.is_a? String
    raise(SizeError, "sig: 64 bytes") unless sig.bytesize == 64
    raise(EncodingError, "sig: binary") unless sig.encoding == Encoding::BINARY

    # BIP340: Let P = lift_x(int(pk))
    p = lift_x(int(pk))

    # BIP340: Let r = int(sig[0:32]) fail if r >= p
    r = int(sig[0..31])
    raise(BoundsError, "r >= p") if r >= P

    # BIP340: Let s = int(sig[32:64]); fail if s >= n
    s = int(sig[32..-1])
    raise(BoundsError, "s >= n") if s >= N

    # BIP340:
    #   Let e = int(hash[BIP0340/challenge](bytes(r) || bytes(P) || m)) mod n
    e = bytes(r) + bytes(p) + m
    e = int(tagged_hash('BIP0340/challenge', e)) % N

    # BIP340: Let R = s . G - e . P
    big_r = dot_group(s) + p.multiply_by_scalar(e).negate

    # BIP340: Fail if is_infinite(R)
    # BIP340: Fail if not has_even_y(R)
    # BIP340: Fail if x(R) != r
    # BIP340 return success iff no failure occurred before reaching this point
    raise(VerifyFail, "R is infinite") if big_r.infinity?
    raise(VerifyFail, "R has odd y") unless big_r.y.even?
    raise(VerifyFail, "R has wrong x") if big_r.x != r
    true
  end

  # BIP340: The function lift_x(x), where x is a 256-bit unsigned integer,
  #         returns the point P for which x(P) = x[10] and has_even_y(P),
  #         or fails if x is greater than p-1 or no such point exists.
  # Note: this deals with P (the prime) and not N (the order)
  def self.lift_x(x)
    raise(TypeError, "x: integer") unless x.is_a? Integer

    # BIP340: Fail if x >= p
    raise(BoundsError, "x") if x >= P or x <= 0

    # BIP340: Let c = x^3 + 7 mod p
    c = (x**3 + 7) % P

    # BIP340: Let y = c ^ ((p + 1) / 4) mod p
    # y = (c ** ((P + 1) / 4)) % P
    y = c.pow((P + 1) / 4, P)

    # BIP340: Fail if c != y^2 mod p
    raise(SanityCheck, "c != y^2 mod p") if c != (y**2) % P

    # BIP340: Return the unique point P such that:
    #   x(P) = x and y(P) = y    if y mod 2 = 0
    #   y(P) = p - y             otherwise
    GROUP.new_point [x, (y % 2 == 0) ? y : P - y]
  end

  # Input
  #   The secret key, sk: 32 bytes binary
  def self.pubkey(sk)
    # BIP340: Let d' = int(sk)
    d0 = int(sk)

    # BIP340: Fail if d' = 0 or d' >= n
    raise(BoundsError, "d0") if d0 <= 0 or d0 >= N

    # BIP340: Return bytes(d' . G)
    bytes(dot_group(d0))
  end

  # generate a new keypair based on random data
  def self.keypair
    sk = Random.bytes(32)
    [sk, pubkey(sk)]
  end

  # as above, but using SecureRandom
  def self.secure_keypair
    sk = SecureRandom.bytes(32)
    [sk, pubkey(sk)]
  end
end
