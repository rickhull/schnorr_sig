require 'ecdsa_ext'
autoload :SecureRandom, 'securerandom'

# This implementation is based on the spec: https://bips.xyz/340
module SchnorrSig
  class Error < RuntimeError; end
  class BoundsError < Error; end
  class SizeError < Error; end
  class TypeError < Error; end
  class SanityCheck < Error; end
  class EncodingError < Error; end
  class VerifyFail < Error; end

  GROUP = ECDSA::Group::Secp256k1
  N = GROUP.order       # smaller than 256**32
  P = GROUP.field.prime # smaller than N
  B = GROUP.byte_length # 32

  # likely returns a Bignum, larger than a 64-bit hardware integer
  def self.bin2big(str)
    bin2hex(str).to_i(16)
  end

  # convert a giant integer to a binary string
  def self.big2bin(bignum)
    # much faster than ECDSA::Format -- thanks ParadoxV5
    hex2bin(bignum.to_s(16).rjust(B * 2, '0'))
  end

  # convert a binary string to a lowercase hex string
  def self.bin2hex(str)
    str.unpack1('H*')
  end

  # convert a hex string to a binary string
  def self.hex2bin(hex)
    [hex].pack('H*')
  end

  # val (dot) G, returns ECDSA::Point
  def self.dot_group(val)
    # ecdsa_ext uses jacobian projection: 10x faster than GROUP.generator * val
    (GROUP.generator.to_jacobian * val).to_affine
  end

  # returns even_val or N - even_val
  def self.select_even_y(point, even_val)
    point.y.even? ? even_val : N - even_val
  end

  # int(x) function signature matches BIP340, returns a bignum (presumably)
  class << self
    alias_method :int, :bin2big
  end

  # bytes(val) function signature matches BIP340, returns a binary string
  def self.bytes(val)
    case val
    when Integer
      # BIP340: The function bytes(x), where x is an integer,
      # returns the 32-byte encoding of x, most significant byte first.
      big2bin(val)
    when ECDSA::Point
      # BIP340: The function bytes(P), where P is a point, returns bytes(x(P)).
      val.infinity? ? ("\x00" * B).b : big2bin(val.x)
    else
      raise(SanityCheck, val.inspect)
    end
  end

  # Input
  #   The secret key, sk:       32 bytes binary
  #   The message, m:           binary
  #   Auxiliary random data, a: 32 bytes binary
  # Note: this deals with N (the order) and not P (the prime)
  def self.sign(sk, m, a = Random.bytes(B))
    raise(TypeError, "sk: string") unless sk.is_a? String
    raise(SizeError, "sk: 32 bytes") unless sk.bytesize == B
    raise(EncodingError, "sk: binary") unless sk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String
    raise(TypeError, "a: string") unless a.is_a? String
    raise(SizeError, "a: 32 bytes") unless a.bytesize == B
    raise(EncodingError, "a: binary") unless a.encoding == Encoding::BINARY

    # BIP340: Let d' = int(sk)
    # BIP340: Fail if d' = 0 or d' >= n
    d0 = int(sk)
    raise(BoundsError, "d0") if !d0.positive? or d0 >= N

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
    # BIP340: Fail if k' = 0
    k0 = int(nonce) % N
    raise(BoundsError, "k0") if !k0.positive?

    # BIP340: Let R = k' . G
    r = dot_group(k0) # this is a point on the elliptic curve
    bytes_r = bytes(r)

    # BIP340: Let k = k' if has_even_y(R), otherwise let k = n - k'
    k = select_even_y(r, k0)

    # BIP340:
    #   Let e = int(hash[BIP0340/challenge](bytes(R) || bytes(P) || m)) mod n
    e = int(tagged_hash('BIP0340/challenge', bytes_r + bytes_p + m)) % N

    # BIP340: Let sig = bytes(R) || bytes((k + ed) mod n)
    # BIP340: Fail unless Verify(bytes(P), m, sig)
    # BIP340: Return the signature sig
    sig = bytes_r + bytes((k + e * d) % N)
    raise(VerifyFail) unless verify(bytes_p, m, sig)
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
    raise(SizeError, "pk: 32 bytes") unless pk.bytesize == B
    raise(EncodingError, "pk: binary") unless pk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String
    raise(TypeError, "sig: string") unless sig.is_a? String
    raise(SizeError, "sig: 64 bytes") unless sig.bytesize == B * 2
    raise(EncodingError, "sig: binary") unless sig.encoding == Encoding::BINARY

    # BIP340: Let P = lift_x(int(pk))
    p = lift_x(int(pk))

    # BIP340: Let r = int(sig[0:32]) fail if r >= p
    r = int(sig[0..B-1])
    raise(BoundsError, "r >= p") if r >= P

    # BIP340: Let s = int(sig[32:64]); fail if s >= n
    s = int(sig[B..-1])
    raise(BoundsError, "s >= n") if s >= N

    # BIP340:
    #   Let e = int(hash[BIP0340/challenge](bytes(r) || bytes(P) || m)) mod n
    e = bytes(r) + bytes(p) + m
    e = int(tagged_hash('BIP0340/challenge', e)) % N

    # BIP340: Let R = s . G - e . P
    # BIP340: Fail if is_infinite(R)
    # BIP340: Fail if not has_even_y(R)
    # BIP340: Fail if x(R) != r
    # BIP340: Return success iff no failure occurred before reaching this point
    big_r = dot_group(s) + p.multiply_by_scalar(e).negate
    !big_r.infinity? and big_r.y.even? and big_r.x == r
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
    c = (x.pow(3, P) + 7) % P

    # BIP340: Let y = c ^ ((p + 1) / 4) mod p
    y = c.pow((P + 1) / 4, P) # use pow to avoid Bignum overflow

    # BIP340: Fail if c != y^2 mod p
    raise(SanityCheck, "c != y^2 mod p") if c != y.pow(2, P)

    # BIP340: Return the unique point P such that:
    #   x(P) = x and y(P) = y    if y mod 2 = 0
    #   y(P) = p - y             otherwise
    GROUP.new_point [x, y.even? ? y : P - y]
  end

  # Input
  #   The secret key, sk: 32 bytes binary
  def self.pubkey(sk)
    # BIP340: Let d' = int(sk)
    # BIP340: Fail if d' = 0 or d' >= n
    # BIP340: Return bytes(d' . G)
    d0 = int(sk)
    raise(BoundsError, "d0") if !d0.positive? or d0 >= N
    bytes(dot_group(d0))
  end

  # generate a new keypair based on random data
  def self.keypair
    sk = Random.bytes(B)
    [sk, pubkey(sk)]
  end

  # as above, but using SecureRandom
  def self.secure_keypair
    sk = SecureRandom.bytes(B)
    [sk, pubkey(sk)]
  end
end

if __FILE__ == $0
  msg = 'hello world'
  sk, pk = SchnorrSig.keypair
  puts "Message: #{msg}"
  puts "Secret key: #{SchnorrSig.bin2hex(sk)}"

  sig = SchnorrSig.sign(sk, msg)
  puts
  puts "Verified signature: #{SchnorrSig.bin2hex(sig)}"
  puts "Encoding: #{sig.encoding}"
  puts "Length: #{sig.length}"
end
