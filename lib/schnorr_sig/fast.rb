require 'rbsecp256k1'

module SchnorrFast
  CONTEXT = Secp256k1::Context.create
  Error = Secp256k1::Error # to enable: rescue SchnorrFast::Error
  class TypeError < Error; end
  class SizeError < Error; end
  class EncodingError < Error; end

  # Input
  #   The secret key, sk: 32 bytes binary
  #   The message, m:     binary
  # Output
  #   64 bytes binary
  def self.sign(sk, m)
    raise(TypeError, "sk: string") unless sk.is_a? String
    raise(SizeError, "sk: 32 bytes") unless sk.bytesize == B
    raise(EncodingError, "sk: binary") unless sk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String

    CONTEXT.sign_schnorr(key_pair(sk), msg).serialized
  end

  # Input
  #   The public key, pk: 32 bytes binary
  #   The message, m:     binary
  #   A signature, sig:   64 bytes binary
  # Output
  #   Boolean, may raise SchnorrFast::Error
  def self.verify(pk, m, sig)
    raise(TypeError, "pk: string") unless pk.is_a? String
    raise(SizeError, "pk: 32 bytes") unless pk.bytesize == 32
    raise(EncodingError, "pk: binary") unless pk.encoding == Encoding::BINARY
    raise(TypeError, "m: string") unless m.is_a? String
    raise(TypeError, "sig: string") unless sig.is_a? String
    raise(SizeError, "sig: 64 bytes") unless sig.bytesize == 64
    raise(EncodingError, "sig: binary") unless sig.encoding == Encoding::BINARY

    signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
  end

  # Input
  #   (The secret key, sk: 32 bytes binary)
  # Output
  #   Secp256k1::KeyPair
  def self.key_pair(sk = nil)
    if sk
      raise(TypeError, "sk: string") unless sk.is_a? String
      CONTEXT.key_pair_from_private_key(sk)
    else
      CONTEXT.generate_key_pair
    end
  end

  # Input
  #   (The secret key, sk: 32 bytes binary)
  # Output
  #   [sk, pk]
  def self.keypair(sk = nil)
    kp = self.key_pair(sk)
    [kp.private_key.data, kp.xonly_public_key.serialized]
  end

  # Input
  #   The signature, str: 64 bytes binary
  # Output
  #   Secp256k1::SchnorrSignature
  def self.signature(str)
    raise(TypeError, "str: string") unless str.is_a? String
    raise(SizeError, "str: 64 bytes") unless str.bytesize == 64
    raise(EncodingError, "str: binary") unless str.encoding == Encoding::BINARY
    Secp256k1::SchnorrSignature.from_data(str)
  end
end
