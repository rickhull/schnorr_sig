require 'schnorr_sig/fast'
require 'minitest/autorun'

include SchnorrSig

describe Fast do
  describe "keys" do
    it "generates a Secp256k1::KeyPair" do
      kp = Fast.keypair_obj
      expect(kp).must_be_kind_of Secp256k1::KeyPair

      kp = Fast.keypair_obj(Random.bytes(32))
      expect(kp).must_be_kind_of Secp256k1::KeyPair
    end

    it "extracts 32 byte binary strings from KeyPair" do
      keys = Fast.extract_keys(Fast.keypair_obj)
      keys.each { |key|
        expect(key).must_be_kind_of String
        expect(key.length).must_equal 32
        expect(key.encoding).must_equal Encoding::BINARY
      }
    end

    it "generates a pubkey for any secret key" do
      sk = Random.bytes(32)
      pk = Fast.pubkey(sk)
      expect(pk).must_be_kind_of String
      expect(pk.length).must_equal 32
      expect(pk.encoding).must_equal Encoding::BINARY
    end

    it "generates a keypair of 32 byte binary strings" do
      keys = Fast.keypair
      keys.each { |key|
        expect(key).must_be_kind_of String
        expect(key.length).must_equal 32
        expect(key.encoding).must_equal Encoding::BINARY
      }
    end
  end

  describe "signatures" do
    it "generates a Secp256k1::SchnorrSignature" do
      sk = Random.bytes(32)
      m = Fast.tagged_hash('test', 'hello world')
      sig = Fast.sign(sk, m)
      obj = Fast.signature(sig)
      expect(obj).must_be_kind_of Secp256k1::SchnorrSignature
    end

    it "signs a message with a 64 byte binary signature" do
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
  end

  it "implements tagged hashes" do
    # SHA256.digest
    h = Fast.tagged_hash('BIP0340/challenge', 'hello world')
    expect(h).must_be_kind_of String
    expect(h.length).must_equal 32
    expect(h.encoding).must_equal Encoding::BINARY
  end
end
