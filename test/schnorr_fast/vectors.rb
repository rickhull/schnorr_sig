require 'csv'
require 'schnorr_fast'

path = File.join(__dir__, '..', 'vectors.csv')
table = CSV.read(path, headers: true)

success = []
failure = []

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

  if SchnorrFast.verify(pk, m, sig) == result
    success << row
  else
    failure << row
  end
  print '.'
}
puts

puts "Success: #{success.count}"
puts "Failure: #{failure.count}"

exit failure.count
