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
      if sk.nil?
        CONTEXT.generate_key_pair
      else
        CONTEXT.key_pair_from_private_key(binary!(sk, KEY))
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
      Secp256k1::SchnorrSignature.from_data(binary!(str, SIG))
    end

    # Input
    #   The secret key, sk: 32 bytes binary
    #   The message, m:     32 byte hash value
    # Output
    #   64 bytes binary
    def sign(sk, m) = CONTEXT.sign_schnorr(keypair_obj(sk),
                                           binary!(m, 32)).serialized

    # Input
    #   The public key, pk: 32 bytes binary
    #   The message, m:     32 byte hash value
    #   A signature, sig:   64 bytes binary
    # Output
    #   Boolean, may raise SchnorrSig::Error, Secp256k1::Error
    def verify?(pk, m, sig)
      binary!(pk, KEY) and binary!(m, 32) and binary!(sig, SIG)
      signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
    end

    # as above but swallow internal errors and return false
    def soft_verify?(pk, m, sig)
      begin
        verify?(pk, m, sig)
      rescue Secp256k1::Error
        false
      end
    end

    #
    # Utility
    #

    # Input
    #   tag: UTF-8 > binary > agnostic
    #   msg: UTF-8 / binary / agnostic
    # Output
    #   32 bytes binary
    def tagged_hash(tag, msg) = CONTEXT.tagged_sha256(str!(tag), str!(msg))
  end

  Fast.include Utils
  Fast.extend Fast
end
