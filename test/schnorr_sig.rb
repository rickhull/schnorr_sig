require 'schnorr_sig'
require 'minitest/autorun'

describe SchnorrSig do
  describe "error classes" do
  end

  describe "validation functions" do
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
