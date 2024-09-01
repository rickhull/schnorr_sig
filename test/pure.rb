require 'schnorr_sig/pure'
require 'minitest/autorun'

include SchnorrSig

ENV['NO_SECURERANDOM'] = '1'

describe Pure do
  describe "Utils" do
    it "converts any integer to a point on the curve" do
      expect(Pure.point(99)).must_be_kind_of ECDSA::Point
      expect(Pure.point(0).infinity?).must_equal true
      p1 = Pure.point(1)
      expect(p1.x).must_be :>, 999_999
      expect(p1.y).must_be :>, 999_999
    end

    it "selects (x) or (N-x), if point.y is even or odd" do
      even_y = Pure.point(99)
      expect(even_y.y.even?).must_equal true

      expect(Pure.select_even_y(even_y, 0)).must_equal 0
      expect(Pure.select_even_y(even_y, 1)).must_equal 1

      odd_y = Pure.point(10)
      expect(odd_y.y.even?).must_equal false

      expect(Pure.select_even_y(odd_y, 0)).wont_equal 0
      expect(Pure.select_even_y(odd_y, 1)).wont_equal 1
    end

    it "converts up to 64 byte binary values to large integers" do
      b32 = Random.bytes(32)
      expect(b32).must_be_kind_of String
      expect(b32.length).must_equal 32
      b64 = Random.bytes(64)

      i32 = Pure.int(b32)     # Pure.int() is an alias to bin2big()
      i64 = Pure.bin2big(b64) # this comes from schnorr_sig/utils.rb

      expect(i32).must_be_kind_of Integer
      expect(i32.positive?).must_equal true

      expect(i64).must_be :>, i32

      expect(Pure.int("\x00")).must_equal 0
      expect(Pure.int("\x00\xFF")).must_equal 255
    end

    it "converts an integer or point to a binary string" do
      str = Pure.bytes(0)
      expect(str).must_be_kind_of String
      expect(str.length).must_equal 32
      expect(str).must_equal ("\x00" * 32).b

      p = Pure.point(1234)
      expect(Pure.bytes(p)).must_equal Pure.big2bin(p.x)
    end

    it "implements lift_x()" do
      expect(Pure.lift_x(1)).must_be_kind_of ECDSA::Point
    end

    it "implements tagged hashes" do
      h = Pure.tagged_hash('BIP0340/challenge', 'hello world') # SHA256
      expect(h).must_be_kind_of String
      expect(h.length).must_equal 32
      expect(h.encoding).must_equal Encoding::BINARY
    end
  end

  describe "Keys" do
    it "generates a pubkey for any secret key value" do
      sk = Random.bytes(32)
      pk = Pure.pubkey(sk)
      expect(pk).must_be_kind_of String
      expect(pk.length).must_equal 32
      expect(pk.encoding).must_equal Encoding::BINARY
    end

    it "generates a keypair of 32 byte binary values" do
      keys = Pure.keypair
      keys.each { |key|
        expect(key).must_be_kind_of String
        expect(key.length).must_equal 32
        expect(key.encoding).must_equal Encoding::BINARY
      }
    end
  end

  describe "Signatures" do
    it "signs a message" do
      sk = Random.bytes(32)
      m = 'hello world'

      # typically you want to just sign the hash of the message (SHA256)
      # but sure, you can sign the message itself
      sig = Pure.sign(sk, m)
      expect(sig).must_be_kind_of String
      expect(sig.length).must_equal 64
      expect(sig.encoding).must_equal Encoding::BINARY
    end

    it "verifies signatures" do
      sk, pk = Pure.keypair
      m = 'hello world'
      sig = Pure.sign(sk, m)
      expect(Pure.verify?(pk, m, sig)).must_equal true
    end
  end
end
