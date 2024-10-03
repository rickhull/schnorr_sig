module SchnorrSig
  class Error < RuntimeError; end
  class SpecError < Error; end

  KEY = 32 # bytes
  SIG = 64 # bytes

  module Utils
    # raise SpecError or return val
    def check!(val, cls)
      val.is_a?(cls) ? val : raise(SpecError, "#{cls}: #{val.inspect}")
    end

    # raise SpecError or return str
    def str!(str, length = nil)
      if check!(str, String) and !length.nil? and length != str.length
        raise(SpecError, "Length #{str.length} should be #{length}")
      end
      str
    end

    # raise SpecError or return str
    def binary!(str, length)
      if str!(str, length).encoding != Encoding::BINARY
        raise(SpecError, "Encoding: #{str.encoding}")
      end
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

    # use SecureRandom unless ENV['NO_SECURERANDOM'] is nonempty
    def random_bytes(count)
      nsr = ENV['NO_SECURERANDOM']
      (nsr and !nsr.empty?) ? Random.bytes(count) : SecureRandom.bytes(count)
    end
  end
end
