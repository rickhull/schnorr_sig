module SchnorrSig
  class Error < RuntimeError; end
  class SizeError < Error; end

  KEY = 32 # bytes
  SIG = 64 # bytes

  module Utils
    # raise TypeError or return val
    def check!(val, cls)
      val.is_a?(cls) ? val : raise(TypeError, "#{cls}: #{val.inspect}")
    end

    # raise TypeError, EncodingError, or SizeError, or return str
    def binary!(str, length)
      check!(str, String)
      raise(EncodingError, str.encoding) if str.encoding != Encoding::BINARY
      raise(SizeError, str.length) if str.length != length
      str
    end

    # likely returns a Bignum, larger than a 64-bit hardware integer
    def bin2big(str) = bin2hex(str).to_i(16)

    # convert a giant integer to a binary string
    def big2bin(bignum) = hex2bin(bignum.to_s(16).rjust(64, '0'))

    # convert a binary string to a lowercase hex string
    def bin2hex(str) = str.unpack1('H*')

    # convert a hex string to a binary string
    def hex2bin(hex) = [hex].pack('H*')
  end
end