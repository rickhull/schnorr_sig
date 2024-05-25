module SchnorrSig
  class InternalError < RuntimeError; end
  class SizeError < InternalError; end
  class TypeError < InternalError; end
  class EncodingError < InternalError; end

  # true or raise
  def self.integer!(i)
    i.is_a?(Integer) or raise(TypeError, i.class)
  end

  # true or raise
  def self.string!(str)
    str.is_a?(String) or raise(TypeError, str.class)
  end

  # true or raise
  def self.bytestring!(str, size)
    string!(str)
    raise(EncodingError, str.encoding) unless str.encoding == Encoding::BINARY
    str.size == size or raise(SizeError, str.size)
  end

  # likely returns a Bignum, larger than a 64-bit hardware integer
  def self.bin2big(str)
    bin2hex(str).to_i(16)
  end

  # convert a giant integer to a binary string
  def self.big2bin(bignum)
    # much faster than ECDSA::Format -- thanks ParadoxV5
    hex2bin(bignum.to_s(16).rjust(B * 2, '0'))
  end

  # convert a binary string to a lowercase hex string
  def self.bin2hex(str)
    str.unpack1('H*')
  end

  # convert a hex string to a binary string
  def self.hex2bin(hex)
    [hex].pack('H*')
  end
end
