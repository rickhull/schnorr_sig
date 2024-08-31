module SchnorrSig
  class Error < RuntimeError; end
  class SizeError < Error; end

  # raise TypeError or return val
  def self.check!(val, cls)
    val.is_a?(cls) ? val : raise(TypeError, "#{cls} expected: #{val.inspect}")
  end

  # raise TypeError, EncodingError, or SizeError, or return str
  def self.binary!(str, length)
    check!(str, String)
    raise(EncodingError, str.encoding) if str.encoding != Encoding::BINARY
    raise(SizeError, str.length) if str.length != length
    str
  end

  # likely returns a Bignum, larger than a 64-bit hardware integer
  def self.bin2big(str)
    bin2hex(str).to_i(16)
  end

  # convert a giant integer to a binary string
  def self.big2bin(bignum)
    # much faster than ECDSA::Format -- thanks ParadoxV5
    hex2bin(bignum.to_s(16).rjust(64, '0'))
  end

  # convert a binary string to a lowercase hex string
  def self.bin2hex(str)
    str.unpack1('H*').to_s
  end

  # convert a hex string to a binary string
  def self.hex2bin(hex)
    [hex].pack('H*')
  end
end
