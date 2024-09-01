require 'schnorr_sig/fast'
require 'minitest/autorun'

describe SchnorrSig do
  it "signs a message" do
    sk = Random.bytes(32)
    m = 'hello world'.ljust(32, ' ')
    sig = SchnorrSig.sign(sk, m)
    expect(sig).must_be_kind_of String
    expect(sig.length).must_equal 64
    expect(sig.encoding).must_equal Encoding::BINARY
  end

  it "verifies signatures" do
    sk, pk = SchnorrSig.keypair
    m = 'hello world'.ljust(32, ' ')
    sig = SchnorrSig.sign(sk, m)
    expect(SchnorrSig.verify?(pk, m, sig)).must_equal true
  end

  it "generates a pubkey for any secret key value" do
    sk = Random.bytes(32)
    pk = SchnorrSig.pubkey(sk)
    expect(pk).must_be_kind_of String
    expect(pk.length).must_equal 32
    expect(pk.encoding).must_equal Encoding::BINARY
  end
end
