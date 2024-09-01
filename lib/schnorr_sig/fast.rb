require 'schnorr_sig/utils'
require 'rbsecp256k1' # gem, C extension

module SchnorrSig
  CONTEXT = Secp256k1::Context.create

  # KeyPair
  # - Create / Split
  #   * Context.create.generate_keypair => KeyPair
  #   * KeyPair#xonly_public_key => XOnlyPublicKey
  #   * KeyPair#private_key => PrivateKey
  # - String Conversion
  #   * Context.create.keypair_from_private_key(sk) => KeyPair
  #   * XOnlyPublicKey.from_data(pk) => XOnlyPublicKey
  #   * XOnlyPublicKey#serialized => pk
  #   * PrivateKey#data => sk

  # Signature
  # - Sign / Verify
  #   * Context.create.sign_schnorr(KeyPair, m) => Signature
  #   * Signature#verify(m, XOnlyPublicKey) => bool
  # - String Conversion
  #   * Signature#serialized => sig (64B String)
  #   * Signature#from_data(sig) => Signature

  module Fast

    #
    # Keys
    #

    # Input
    #   (The secret key, sk: 32 bytes binary)
    # Output
    #   Secp256k1::KeyPair
    def keypair_obj(sk = nil)
      if sk
        binary!(sk, KEY)
        CONTEXT.key_pair_from_private_key(sk)
      else
        CONTEXT.generate_key_pair
      end
    end

    # Input
    #   Secp256k1::KeyPair
    # Output
    #  [sk, pk] (32 bytes binary)
    def extract_keys(keypair_obj)
      [keypair_obj.private_key.data, keypair_obj.xonly_public_key.serialized]
    end

    # Input
    #   The secret key, sk: 32 bytes binary
    # Output
    #   The public key: 32 bytes binary
    def pubkey(sk) = keypair_obj(sk).xonly_public_key.serialized

    # Output
    #   [sk, pk] (32 bytes binary)
    def keypair = extract_keys(keypair_obj())

    #
    # Signatures
    #

    # Input
    #   The signature, str: 64 bytes binary
    # Output
    #   Secp256k1::SchnorrSignature
    def signature(str)
      binary!(str, SIG)
      Secp256k1::SchnorrSignature.from_data(str)
    end

    # Input
    #   The secret key, sk: 32 bytes binary
    #   The message, m:     32 byte hash value
    # Output
    #   64 bytes binary
    def sign(sk, m)
      binary!(sk, KEY) and binary!(m, 32)
      CONTEXT.sign_schnorr(keypair_obj(sk), m).serialized
    end

    # Input
    #   The public key, pk: 32 bytes binary
    #   The message, m:     32 byte hash value
    #   A signature, sig:   64 bytes binary
    # Output
    #   Boolean, may raise SchnorrSig::Error, Secp256k1::Error
    def strict_verify?(pk, m, sig)
      binary!(pk, KEY) and binary!(m, 32) and binary!(sig, SIG)
      signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
    end

    # as above but swallow errors and return false
    def verify?(pk, m, sig) = strict_verify?(pk, m, sig) rescue false

    #
    # Utility
    #

    # Input
    #   tag: UTF-8 > binary > agnostic
    #   msg: UTF-8 / binary / agnostic
    # Output
    #   32 bytes binary
    def tagged_hash(tag, msg)
      check!(tag, String) and check!(msg, String)
      CONTEXT.tagged_sha256(tag, msg)
    end
  end

  Fast.include(Utils)
  Fast.extend(Fast)
end

if __FILE__ == $0
  include SchnorrSig

  msg = 'hello world'
  hsh = Fast.tagged_hash('test', msg)

  sk, pk = Fast.keypair
  puts "Message: #{msg}"
  puts "Hash: #{Fast.bin2hex(hsh)}"
  puts "Secret key: #{Fast.bin2hex(sk)}"
  puts "Public key: #{Fast.bin2hex(pk)}"
  puts

  sig = Fast.sign(sk, hsh)
  puts "Signature: #{Fast.bin2hex(sig)}"
  puts "Encoding: #{sig.encoding}"
  puts "Length: #{sig.length}"
  puts "Verified: #{Fast.verify?(pk, hsh, sig)}"
end
