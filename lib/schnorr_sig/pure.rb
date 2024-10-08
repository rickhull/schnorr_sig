require 'schnorr_sig/utils'
require 'ecdsa_ext'                    # gem, depends on ecdsa gem
autoload :SecureRandom, 'securerandom' # stdlib

# This implementation is based on the BIP340 spec: https://bips.xyz/340
module SchnorrSig
  class SanityCheck < Error; end

  GROUP = ECDSA::Group::Secp256k1
  P = GROUP.field.prime # smaller than 256**32
  N = GROUP.order       # smaller than P
  B = GROUP.byte_length # 32

  module Pure

    #
    # Utils
    #

    # int (dot) G, returns ECDSA::Point
    def point(int)
      (GROUP.generator.to_jacobian * int).to_affine # 10x faster via ecdsa_ext
    end

    # returns even_val or N - even_val
    def select_even_y(point, even_val)
      point.y.even? ? even_val : N - even_val
    end

    # int(x) function signature matches BIP340, returns a bignum (presumably)
    def int(x) = bin2big(x)

    # bytes(val) function signature matches BIP340, returns a binary string
    def bytes(val)
      case val
      when Integer
        # BIP340: The function bytes(x), where x is an integer,
        # returns the 32-byte encoding of x, most significant byte first.
        big2bin(val)
      when ECDSA::Point
        # BIP340: The function bytes(P), where P is a point,
        # returns bytes(x(P)).
        val.infinity? ? raise(SanityCheck, val.inspect) : big2bin(val.x)
      else
        raise(SanityCheck, val.inspect)
      end
    end

    # BIP340: The function lift_x(x), where x is a 256-bit unsigned integer,
    #         returns the point P for which x(P) = x and has_even_y(P),
    #         or fails if x is greater than p-1 or no such point exists.
    # Input
    #   A large integer, x
    # Output
    #   ECDSA::Point
    def lift_x(x)
      check!(x, Integer)

      # BIP340: Fail if x >= p
      raise(SanityCheck, "x") if x >= P or x <= 0

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

    # see https://bips.xyz/340#design (Tagged hashes)
    # Input
    #   A tag:            UTF-8 > binary > agnostic
    #   The payload, msg: UTF-8 / binary / agnostic
    # Output
    #   32 bytes binary
    def tagged_hash(tag, msg)
      # BIP340: The function hash[name](x) where x is a byte array
      #         returns the 32-byte hash
      #         SHA256(SHA256(tag) || SHA256(tag) || x)
      #         where tag is the UTF-8 encoding of name.
      tag_hash = Digest::SHA256.digest tag
      Digest::SHA256.digest(tag_hash + tag_hash + str!(msg).b)
    end

    #
    # Keys
    #

    # Input
    #   The secret key, sk: 32 bytes binary
    # Output
    #   32 bytes binary (represents P.x for point P on the curve)
    def pubkey(sk)
      binary!(sk, KEY)

      # BIP340: Let d' = int(sk)
      # BIP340: Fail if d' = 0 or d' >= n
      # BIP340: Return bytes(d' . G)
      d0 = int(sk)
      raise(SanityCheck, "d0") if !d0.positive? or d0 >= N
      bytes(point(d0))
    end

    # generate a new keypair based on random data
    def keypair
      sk = random_bytes(KEY)
      [sk, pubkey(sk)]
    end

    #
    # Signatures
    #

    # Input
    #   The secret key, sk:       32 bytes binary
    #   The message, m:           binary / UTF-8 / agnostic
    #   Auxiliary random data, a: 32 bytes binary
    # Output
    #   The signature, sig:       64 bytes binary
    def sign(sk, m, auxrand: nil)
      a = auxrand.nil? ? random_bytes(B) : auxrand
      binary!(sk, KEY) and str!(m) and binary!(a, B)

      # BIP340: Let d' = int(sk)
      # BIP340: Fail if d' = 0 or d' >= n
      d0 = int(sk)
      raise(SanityCheck, "d0") if !d0.positive? or d0 >= N

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
      raise(SanityCheck, "k0") if !k0.positive?

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
      raise(SanityCheck, "sig did not verify") unless verify?(bytes_p, m, sig)
      sig
    end

    # Input
    #   The public key, pk: 32 bytes binary
    #   The message, m:     UTF-8 / binary / agnostic
    #   A signature, sig:   64 bytes binary
    # Output
    #   Boolean
    def verify?(pk, m, sig)
      binary!(pk, KEY) and str!(m) and binary!(sig, SIG)

      # BIP340: Let P = lift_x(int(pk))
      p = lift_x(int(pk))

      # BIP340: Let r = int(sig[0:32]) fail if r >= p
      r = int(sig[0..KEY-1])
      raise(SanityCheck, "r >= p") if r >= P

      # BIP340: Let s = int(sig[32:64]); fail if s >= n
      s = int(sig[KEY..-1])
      raise(SanityCheck, "s >= n") if s >= N

      # BIP340:
      #   Let e = int(hash[BIP0340/challenge](bytes(r) || bytes(P) || m)) mod n
      e = bytes(r) + bytes(p) + m
      e = int(tagged_hash('BIP0340/challenge', e)) % N

      # BIP340: Let R = s . G - e . P
      # BIP340: Fail if is_infinite(R)
      # BIP340: Fail if not has_even_y(R)
      # BIP340: Fail if x(R) != r
      # BIP340: Return success iff no prior failure
      big_r = point(s) + p.multiply_by_scalar(e).negate
      !big_r.infinity? and big_r.y.even? and big_r.x == r
    end

    # as above but swallow internal errors and return false
    def soft_verify?(pk, m, sig)
      begin
        verify?(pk, m, sig)
      rescue SanityCheck
        false
      end
    end
  end

  Pure.include Utils
  Pure.extend Pure
end
