require 'csv'
require 'rbsecp256k1'

path = File.join(__dir__, '..', 'vectors.csv')
table = CSV.read(path, headers: true)

success = []
failure = []

CONTEXT = Secp256k1::Context.create

def hex2bin(hex)
  [hex].pack('H*')
end

table.each { |row|
  # index
  # secret key
  # public key
  # aux_rand
  # message
  # signature
  # verification result
  # comment

  sk       = hex2bin row.fetch('secret key')
  pk       = hex2bin row.fetch('public key')
  aux_rand = hex2bin row.fetch('aux_rand')
  m        = hex2bin row.fetch('message')
  sig      = hex2bin row.fetch('signature')

  index    = row.fetch('index')
  comment  = row.fetch('comment')
  result   = row.fetch('verification result') == 'TRUE'

  if sk.empty?
    begin
      xopk = Secp256k1::XOnlyPublicKey.from_data(pk)
    rescue Secp256k1::DeserializationError
      if !result
        success << row
      else
        warn "index #{index} failed verification; expected success"
        failure << row
      end
      next
    end
  else
    keypair = CONTEXT.key_pair_from_private_key(sk)
    xopk = keypair.xonly_public_key

    if xopk.serialized != pk
      warn "index #{index} generated public key does not match vectors.csv"
    end
  end
  sig = Secp256k1::SchnorrSignature.from_data(sig)

  begin
    if sig.verify(m, xopk) == result
      success << row
    else
      warn "index #{index} passed verification; expected failure"
      failure << row
    end
  rescue Secp256k1::Error => e
    if !result
      success << row
    else
      warn "index #{index} failed verification; expected success"
      failure << row
    end
  end
  print '.'
}
puts

puts "Success: #{success.count}"
puts "Failure: #{failure.count}"

failure.each { |row| p row }

exit failure.count
