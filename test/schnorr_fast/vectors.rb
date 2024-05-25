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
  sk       = hex2bin row.fetch('secret key')
  pk       = hex2bin row.fetch('public key')
  aux_rand = hex2bin row.fetch('aux_rand')
  m        = hex2bin row.fetch('message')
  sig      = hex2bin row.fetch('signature')

  index    = row.fetch('index')
  comment  = row.fetch('comment')
  expected = row.fetch('verification result') == 'TRUE'

  result = begin
             SchnorrFast.verify(pk, m, sig)
           rescue SchnorrFast::Error
             false
           end
  (result == expected ? success : failure) << row
  print '.'
}
puts

puts "Success: #{success.count}"
puts "Failure: #{failure.count}"

puts failure unless failure.empty?

exit failure.count
