require 'schnorr_sig/common'           # project
require 'ecdsa_ext'                    # gem
autoload :SecureRandom, 'securerandom' # stdlib

# This implementation is based on the BIP340 spec: https://bips.xyz/340
# re-open SchnorrSig to add more functions, errors, and constants
module SchnorrSig
  class Error < RuntimeError; end
  class BoundsError < Error; end
  class SanityCheck < Error; end
  class VerifyFail < Error; end
  class InfinityPoint < Error; end

  GROUP = ECDSA::Group::Secp256k1 # steep:ignore
  P = GROUP.field.prime # smaller than 256**32
  N = GROUP.order       # smaller than P
  B = GROUP.byte_length # 32

  # int (dot) G, returns ECDSA::Point
  def self.point(int)
    # ecdsa_ext uses jacobian projection: 10x faster than GROUP.generator * int
    (GROUP.generator.to_jacobian * int).to_affine
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
    when ECDSA::Point # steep:ignore
      # BIP340: The function bytes(P), where P is a point, returns bytes(x(P)).
      val.infinity? ? raise(InfinityPoint, val.inspect) : big2bin(val.x)
    else
      raise(SanityCheck, val.inspect)
    end
  end

  # Input
  #   The secret key, sk:       32 bytes binary
  #   The message, m:           binary / UTF-8 / agnostic
  #   Auxiliary random data, a: 32 bytes binary
  # Output
  #   The signature, sig:       64 bytes binary
  def self.sign(sk, m, a = Random.bytes(B))
    bytestring!(sk, B) and string!(m) and bytestring!(a, B)

    # BIP340: Let d' = int(sk)
    # BIP340: Fail if d' = 0 or d' >= n
    d0 = int(sk)
    raise(BoundsError, "d0") if !d0.positive? or d0 >= N

    # BIP340: Let P = d' . G
    p = point(d0) # this is a point on the elliptic curve
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
    r = point(k0) # this is a point on the elliptic curve
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
    raise(VerifyFail) unless verify?(bytes_p, m, sig)
    sig
  end

  # see https://bips.xyz/340#design (Tagged hashes)
  # Input
  #   A tag:            UTF-8 > binary > agnostic
  #   The payload, msg: UTF-8 / binary / agnostic
  # Output
  #   32 bytes binary
  def self.tagged_hash(tag, msg)
    string!(tag) and string!(msg)
    warn("tag expected to be UTF-8") unless tag.encoding == Encoding::UTF_8

    # BIP340: The function hash[name](x) where x is a byte array
    #         returns the 32-byte hash
    #         SHA256(SHA256(tag) || SHA256(tag) || x)
    #         where tag is the UTF-8 encoding of name.
    tag_hash = Digest::SHA256.digest(tag)
    Digest::SHA256.digest(tag_hash + tag_hash + msg)
  end

  # Input
  #   The public key, pk: 32 bytes binary
  #   The message, m:     UTF-8 / binary / agnostic
  #   A signature, sig:   64 bytes binary
  # Output
  #   Boolean
  def self.verify?(pk, m, sig)
    bytestring!(pk, B) and string!(m) and bytestring!(sig, B * 2)

    # BIP340: Let P = lift_x(int(pk))
    p = lift_x(int(pk))

    # BIP340: Let r = int(sig[0:32]) fail if r >= p
    r = int(sig[0..B-1]) # steep:ignore
    raise(BoundsError, "r >= p") if r >= P

    # BIP340: Let s = int(sig[32:64]); fail if s >= n
    s = int(sig[B..-1])  # steep:ignore
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
    big_r = point(s) + p.multiply_by_scalar(e).negate
    !big_r.infinity? and big_r.y.even? and big_r.x == r
  end

  # BIP340: The function lift_x(x), where x is a 256-bit unsigned integer,
  #         returns the point P for which x(P) = x and has_even_y(P),
  #         or fails if x is greater than p-1 or no such point exists.
  # Input
  #   A large integer, x
  # Output
  #   ECDSA::Point
  def self.lift_x(x)
    integer!(x)

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
  # Output
  #   32 bytes binary (represents P.x for point P on the curve)
  def self.pubkey(sk)
    bytestring!(sk, B)

    # BIP340: Let d' = int(sk)
    # BIP340: Fail if d' = 0 or d' >= n
    # BIP340: Return bytes(d' . G)
    d0 = int(sk)
    raise(BoundsError, "d0") if !d0.positive? or d0 >= N
    bytes(point(d0))
  end

  # generate a new keypair based on random data
  def self.keypair
    sk = Random.bytes(B)
    [sk, pubkey(sk)]
  end

  # as above, but using SecureRandom
  def self.secure_keypair
    sk = SecureRandom.bytes(B) # steep:ignore
    [sk, pubkey(sk)]
  end
end

if __FILE__ == $0
  msg = 'hello world'
  sk, pk = SchnorrSig.keypair
  puts "Message: #{msg}"
  puts "Secret key: #{SchnorrSig.bin2hex(sk)}"
  puts "Public key: #{SchnorrSig.bin2hex(pk)}"

  sig = SchnorrSig.sign(sk, msg)
  puts
  puts "Verified signature: #{SchnorrSig.bin2hex(sig)}"
  puts "Encoding: #{sig.encoding}"
  puts "Length: #{sig.length}"
end
