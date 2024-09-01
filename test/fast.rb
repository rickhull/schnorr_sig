require 'schnorr_sig/fast'
require 'minitest/autorun'

include SchnorrSig

describe Fast do
  it "signs a message" do
    sk = Random.bytes(32)
    m = Fast.tagged_hash('test', 'hello world')
    sig = Fast.sign(sk, m)
    expect(sig).must_be_kind_of String
    expect(sig.length).must_equal 64
    expect(sig.encoding).must_equal Encoding::BINARY
  end

  it "verifies signatures" do
    sk, pk = Fast.keypair
    m = Fast.tagged_hash('test', 'hello world')
    sig = Fast.sign(sk, m)
    expect(Fast.verify?(pk, m, sig)).must_equal true
  end

  it "generates a pubkey for any secret key value" do
    sk = Random.bytes(32)
    pk = Fast.pubkey(sk)
    expect(pk).must_be_kind_of String
    expect(pk.length).must_equal 32
    expect(pk.encoding).must_equal Encoding::BINARY
  end

  it "implements tagged hashes" do
    # SHA256.digest
    h = Fast.tagged_hash('BIP0340/challenge', 'hello world')
    expect(h).must_be_kind_of String
    expect(h.length).must_equal 32
    expect(h.encoding).must_equal Encoding::BINARY
  end

  it "generates a Secp256k1::KeyPair" do
    kp = Fast.keypair_obj
    expect(kp).must_be_kind_of Secp256k1::KeyPair

    kp = Fast.keypair_obj(Random.bytes(32))
    expect(kp).must_be_kind_of Secp256k1::KeyPair
  end

  it "generates a Secp256k1::SchnorrSignature" do
    sk = Random.bytes(32)
    m = Fast.tagged_hash('test', 'hello world')
    sig = Fast.sign(sk, m)
    obj = Fast.signature(sig)
    expect(obj).must_be_kind_of Secp256k1::SchnorrSignature
  end
end
