require 'schnorr_sig/utils'
require 'minitest/autorun'

include SchnorrSig

Utils.extend(Utils)

describe Utils do
  describe "type enforcement" do
    it "enforces the class of any object" do
      expect(Utils.check!('123', String)).must_equal '123'
      expect(Utils.check!(123, Integer)).must_equal 123
      expect { Utils.check!([], String) }.must_raise TypeError
    end

    it "enforces binary strings: type, encoding, length" do
      expect(Utils.binary!("\x00\x01".b, 2)).must_equal "\x00\x01".b
      expect {
        Utils.binary!("\x00\x01".b, 3)
      }.must_raise SchnorrSig::SizeError
      expect {
        Utils.binary!("\x00\x01", 2)
      }.must_raise EncodingError
    end
  end

  describe "conversion functions" do
    it "converts binary strings (network order, big endian) to integers" do
      expect(Utils.bin2big("\00")).must_equal 0
      expect(Utils.bin2big("\xFF\xFF")).must_equal 65535
    end

    it "converts large integers to binary strings, null padded to 32 bytes" do
      expect(Utils.big2bin(0)).must_equal ("\x00" * 32).b
      expect(Utils.big2bin(1)).must_equal ("\x00" * 31 + "\x01").b
    end

    it "converts binary strings to lowercase hex strings" do
      expect(Utils.bin2hex("\xDE\xAD\xBE\xEF")).must_equal "deadbeef"
    end

    it "converts hex strings to binary strings" do
      expect(Utils.hex2bin("deadbeef")).must_equal "\xDE\xAD\xBE\xEF".b
      expect(Utils.hex2bin("deadbeef")).must_equal "\xde\xad\xbe\xef".b
      expect(Utils.hex2bin("DEADBEEF")).must_equal "\xDE\xAD\xBE\xEF".b
      expect(Utils.hex2bin("DEADBEEF")).must_equal "\xde\xad\xbe\xef".b
    end
  end
end
