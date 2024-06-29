require 'schnorr_sig/pure'
require 'minitest/autorun'

describe SchnorrSig do
  it "converts any integer to a point on the curve" do
    expect(SchnorrSig.point(99)).must_be_kind_of ECDSA::Point
    expect(SchnorrSig.point(0).infinity?).must_equal true
    p1 = SchnorrSig.point(1)
    expect(p1.x).must_be :>, 999_999
    expect(p1.y).must_be :>, 999_999
  end

  it "selects (x) or (N-x), if point.y is even or odd" do
    even_y = SchnorrSig.point(99)
    expect(even_y.y.even?).must_equal true

    expect(SchnorrSig.select_even_y(even_y, 0)).must_equal 0
    expect(SchnorrSig.select_even_y(even_y, 1)).must_equal 1

    odd_y = SchnorrSig.point(10)
    expect(odd_y.y.even?).must_equal false

    expect(SchnorrSig.select_even_y(odd_y, 0)).wont_equal 0
    expect(SchnorrSig.select_even_y(odd_y, 1)).wont_equal 1
  end

  it "converts up to 64 byte binary values to large integers" do
    b32 = Random.bytes(32)
    expect(b32).must_be_kind_of String
    expect(b32.length).must_equal 32
    b64 = Random.bytes(64)

    i32 = SchnorrSig.int(b32)     # SchnorrSig.int() is an alias to bin2big()
    i64 = SchnorrSig.bin2big(b64) # this comes from schnorr_sig/util

    expect(i32).must_be_kind_of Integer
    expect(i32.positive?).must_equal true

    expect(i64).must_be :>, i32

    expect(SchnorrSig.int("\x00")).must_equal 0
    expect(SchnorrSig.int("\x00\xFF")).must_equal 255
  end

  it "converts an integer or point to a binary string" do
    str = SchnorrSig.bytes(0)
    expect(str).must_be_kind_of String
    expect(str.length).must_equal 32
    expect(str).must_equal ("\x00" * 32).b

    p = SchnorrSig.point(1234)
    expect(SchnorrSig.bytes(p)).must_equal SchnorrSig.big2bin(p.x)
  end

  it "signs a message" do
    sk = Random.bytes(32)
    m = 'hello world'
    sig = SchnorrSig.sign(sk, m)
    expect(sig).must_be_kind_of String
    expect(sig.length).must_equal 64
    expect(sig.encoding).must_equal Encoding::BINARY
  end

  it "implements tagged hashes" do
    # SHA256.digest
    h = SchnorrSig.tagged_hash('BIP0340/challenge', 'hello world')
    expect(h).must_be_kind_of String
    expect(h.length).must_equal 32
    expect(h.encoding).must_equal Encoding::BINARY
  end

  it "verifies signatures" do
    sk, pk = SchnorrSig.keypair
    m = 'hello world'
    sig = SchnorrSig.sign(sk, m)
    expect(SchnorrSig.verify?(pk, m, sig)).must_equal true
  end

  it "implements lift_x()" do
    expect(SchnorrSig.lift_x(1)).must_be_kind_of ECDSA::Point
  end

  it "generates a pubkey for any secret key value" do
    sk = Random.bytes(32)
    pk = SchnorrSig.pubkey(sk)
    expect(pk).must_be_kind_of String
    expect(pk.length).must_equal 32
    expect(pk.encoding).must_equal Encoding::BINARY
  end
end
