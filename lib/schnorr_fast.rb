require 'rbsecp256k1'

module SchnorrFast
  CONTEXT = Secp256k1::Context.create
  XOPK = Secp256k1::XOnlyPublicKey
  SSS = Secp256k1::SchnorrSignature

  # returns Secp256k1::SchnorrSignature
  def self.sign(keypair, msg)
    raise(TypeError, keypair.inspect) unless keypair.is_a? Secp256k1::KeyPair
    raise(TypeError, "msg: string") unless msg.is_a? String
    CONTEXT.sign_schnorr(keypair, msg)
  end

  # may raise; returns true or false
  def self.verify(xopk, msg, sig)
    raise(TypeError, "xopk: #{XOPK.name}") unless xopk.is_a? XOPK
    raise(TypeError, "msg: string") unless msg.is_a? String
    raisE(TypeError, "sig: #{SSS.name}") unless sig.is_a? SSS
    sig.verify(msg, xopk)
  end

  def self.keypair(sk = nil)
    if sk
      raise(TypeError, "sk: string") unless sk.is_a? String
      CONTEXT.key_pair_from_private_key(sk)
    else
      CONTEXT.generate_key_pair
    end
  end

  def self.signature(str)
    raise(TypeError, "str: string") unless str.is_a? String
    Secp256k1::SchnorrSignature.from_data(str)
  end
end
