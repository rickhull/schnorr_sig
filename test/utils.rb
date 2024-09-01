require 'schnorr_sig/utils'
require 'minitest/autorun'

SchnorrSig.extend(SchnorrSig::Utils)

describe SchnorrSig do
  describe "type enforcement" do
    it "enforces the class of any object" do
      expect(SchnorrSig.check!('123', String)).must_equal '123'
      expect(SchnorrSig.check!(123, Integer)).must_equal 123
      expect { SchnorrSig.check!([], String) }.must_raise TypeError
    end

    it "enforces binary strings: type, encoding, length" do
      expect(SchnorrSig.binary!("\x00\x01".b, 2)).must_equal "\x00\x01".b
      expect {
        SchnorrSig.binary!("\x00\x01".b, 3)
      }.must_raise SchnorrSig::SizeError
      expect {
        SchnorrSig.binary!("\x00\x01", 2)
      }.must_raise EncodingError
    end
  end

  describe "conversion functions" do
    it "converts binary strings (network order, big endian) to integers" do
      expect(SchnorrSig.bin2big("\00")).must_equal 0
      expect(SchnorrSig.bin2big("\xFF\xFF")).must_equal 65535
    end

    it "converts large integers to binary strings, null padded to 32 bytes" do
      expect(SchnorrSig.big2bin(0)).must_equal ("\x00" * 32).b
      expect(SchnorrSig.big2bin(1)).must_equal ("\x00" * 31 + "\x01").b
    end

    it "converts binary strings to lowercase hex strings" do
      expect(SchnorrSig.bin2hex("\xDE\xAD\xBE\xEF")).must_equal "deadbeef"
    end

    it "converts hex strings to binary strings" do
      expect(SchnorrSig.hex2bin("deadbeef")).must_equal "\xDE\xAD\xBE\xEF".b
      expect(SchnorrSig.hex2bin("DEADBEEF")).must_equal "\xde\xad\xbe\xef".b
    end
  end
end
