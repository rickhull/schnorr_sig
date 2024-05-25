require 'schnorr_sig'
require 'rbsecp256k1'

module SchnorrSig
  CONTEXT = Secp256k1::Context.create
  Error = Secp256k1::Error          # to enable: rescue SchnorrFast::Error

  # Input
  #   The secret key, sk: 32 bytes binary
  #   The message, m:     (binary)
  # Output
  #   64 bytes binary
  def self.sign(sk, m)
    bytestring!(sk, 32) and string!(m)
    CONTEXT.sign_schnorr(key_pair(sk), msg).serialized
  end

  # Input
  #   The public key, pk: 32 bytes binary
  #   The message, m:     binary
  #   A signature, sig:   64 bytes binary
  # Output
  #   Boolean, may raise SchnorrFast::Error
  def self.verify(pk, m, sig)
    bytestring!(pk, 32) and string!(m) and bytestring!(sig, 64)
    signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
  end

  # Input
  #   (The secret key, sk: 32 bytes binary)
  # Output
  #   Secp256k1::KeyPair
  def self.key_pair(sk = nil)
    if sk
      bytestring!(sk, 32)
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
    bytestring!(str, 64)
    Secp256k1::SchnorrSignature.from_data(str)
  end
end