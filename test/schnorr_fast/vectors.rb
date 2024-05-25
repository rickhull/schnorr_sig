require 'csv'
require 'schnorr_sig'
require 'schnorr_sig/fast'

path = File.join(__dir__, '..', 'vectors.csv')
table = CSV.read(path, headers: true)

success = []
failure = []

table.each { |row|
  sk       = SchnorrSig.hex2bin row.fetch('secret key')
  pk       = SchnorrSig.hex2bin row.fetch('public key')
  aux_rand = SchnorrSig.hex2bin row.fetch('aux_rand')
  m        = SchnorrSig.hex2bin row.fetch('message')
  sig      = SchnorrSig.hex2bin row.fetch('signature')

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
