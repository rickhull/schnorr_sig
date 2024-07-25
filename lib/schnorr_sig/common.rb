module SchnorrSig
  class Error < RuntimeError; end
  class SizeError < Error; end
  class TypeError < Error; end
  class EncodingError < Error; end

  # true or raise
  def self.integer!(i)
    i.is_a?(Integer) or raise(TypeError, [i, i.class].join(':'))
  end

  # true or raise
  def self.string!(str)
    str.is_a?(String) or raise(TypeError, [str, str.class].join(':'))
  end

  # true or raise
  def self.bytestring!(str, size)
    string!(str)
    if str.encoding == Encoding::BINARY
      raise(EncodingError, str[0..3].inspect)
    end
    str.bytesize == size or raise(SizeError, str[0..3].inspect)
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
