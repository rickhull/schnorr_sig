require 'schnorr_sig'
require 'rbsecp256k1' # gem, C extension

# re-open SchnorrSig to add more functions, errors, and constants
module SchnorrSig
  CONTEXT = Secp256k1::Context.create
  FORCE_32 = true # currently rbsecp256k1 restricts message size to 32 bytes

  # Input
  #   The secret key, sk: 32 bytes binary
  #   The message, m:     UTF-8 / binary / agnostic
  # Output
  #   64 bytes binary
  def self.sign(sk, m)
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
  def self.strict_verify?(pk, m, sig)
    binary!(pk, KEY) and check!(m, String) and binary!(sig, SIG)
    signature(sig).verify(m, Secp256k1::XOnlyPublicKey.from_data(pk))
  end

  # as above but swallow errors and return false
  def self.verify?(pk, m, sig)
    strict_verify?(pk, m, sig) rescue false
  end

  # This method is native to rbsecp256k1
  # Input
  #   (The secret key, sk: 32 bytes binary)
  # Output
  #   Secp256k1::KeyPair
  def self.key_pair(sk = nil)
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
  def self.keypair
    kp = self.key_pair
    [kp.private_key.data, kp.xonly_public_key.serialized]
  end

  # Input
  #   The secret key, sk: 32 bytes binary
  # Output
  #   The public key: 32 bytes binary
  def self.pubkey(sk)
    self.key_pair(sk).xonly_public_key.serialized
  end

  # Input
  #   The signature, str: 64 bytes binary
  # Output
  #   Secp256k1::SchnorrSignature
  def self.signature(str)
    binary!(str, SIG)
    Secp256k1::SchnorrSignature.from_data(str)
  end
end

if __FILE__ == $0
  msg = 'hello world'.ljust(32, ' ')

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
