require 'schnorr_sig/fast'
require 'minitest/autorun'

include SchnorrSig

describe Fast do
  it "signs a message" do
    sk = Random.bytes(32)
    m = 'hello world'.ljust(32, ' ')
    sig = Fast.sign(sk, m)
    expect(sig).must_be_kind_of String
    expect(sig.length).must_equal 64
    expect(sig.encoding).must_equal Encoding::BINARY
  end

  it "verifies signatures" do
    sk, pk = Fast.keypair
    m = 'hello world'.ljust(32, ' ')
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
end
