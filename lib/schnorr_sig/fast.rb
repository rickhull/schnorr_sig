require 'schnorr_sig/util'
require 'rbsecp256k1' # gem, C extension

# re-open SchnorrSig to add more functions, errors, and constants
module SchnorrSig
  CONTEXT = Secp256k1::Context.create
  Error = Secp256k1::Error # enable: rescue SchnorrSig::Error

  # Input
  #   The secret key, sk: 32 bytes binary
  #   The message, m:     UTF-8 / binary / agnostic
  # Output
  #   64 bytes binary
  def self.sign(sk, m)
    bytestring!(sk, 32) and string!(m)
    # m = m.ljust(32, ' ')
    CONTEXT.sign_schnorr(key_pair(sk), m).serialized
  end

  # Input
  #   The public key, pk: 32 bytes binary
  #   The message, m:     UTF-8 / binary / agnostic
  #   A signature, sig:   64 bytes binary
  # Output
  #   Boolean, may raise SchnorrSig::Error
  def self.verify?(pk, m, sig)
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
