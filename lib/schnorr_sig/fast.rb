require 'schnorr_sig/utils'
require 'rbsecp256k1' # gem, C extension

# this implementation is based on libsecp256k1
module SchnorrSig
  CONTEXT = Secp256k1::Context.create
  FORCE_32 = true # currently rbsecp256k1 restricts message size to 32 bytes

  module Fast
    # Input
    #   The secret key, sk: 32 bytes binary
    #   The message, m:     UTF-8 / binary / agnostic
    # Output
    #   64 bytes binary
    def sign(sk, m)
      binary!(sk, KEY) and check!(m, String)
      raise(SizeError, "32 bytes expected") if FORCE_32 and m.length != 32
      CONTEXT.sign_schnorr(key_pair(sk), m).serialized
    end

    # Input
    #   The public key, pk: 32 bytes binary
    #   The message, m:     UTF-8 / binary / agnostic
    #   A signature, sig:   64 bytes binary
    # Output
    #   Boolean, may raise SchnorrSig::Error, Secp256k1::Error
    def strict_verify?(pk, m, sig)
      binary!(pk, KEY) and check!(m, String) and binary!(sig, SIG)
      signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
    end

    # as above but swallow errors and return false
    def verify?(pk, m, sig)
      strict_verify?(pk, m, sig) rescue false
    end

    # This method is native to rbsecp256k1
    # Input
    #   (The secret key, sk: 32 bytes binary)
    # Output
    #   Secp256k1::KeyPair
    def key_pair(sk = nil)
      if sk
        binary!(sk, KEY)
        CONTEXT.key_pair_from_private_key(sk)
      else
        CONTEXT.generate_key_pair
      end
    end

    # This method matches the pure.rb signature
    # Output
    #   [sk, pk]
    def keypair
      kp = self.key_pair
      [kp.private_key.data, kp.xonly_public_key.serialized]
    end

    # Input
    #   The secret key, sk: 32 bytes binary
    # Output
    #   The public key: 32 bytes binary
    def pubkey(sk)
      self.key_pair(sk).xonly_public_key.serialized
    end

    # Input
    #   The signature, str: 64 bytes binary
    # Output
    #   Secp256k1::SchnorrSignature
    def signature(str)
      binary!(str, SIG)
      Secp256k1::SchnorrSignature.from_data(str)
    end
  end

  Fast.include(Utils)
  Fast.extend(Fast)
end

if __FILE__ == $0
  include SchnorrSig

  msg = 'hello world'.ljust(32, ' ')

  sk, pk = Fast.keypair
  puts "Message: #{msg}"
  puts "Secret key: #{Fast.bin2hex(sk)}"
  puts "Public key: #{Fast.bin2hex(pk)}"

  sig = Fast.sign(sk, msg)
  puts
  puts "Verified signature: #{Fast.bin2hex(sig)}"
  puts "Encoding: #{sig.encoding}"
  puts "Length: #{sig.length}"
end
