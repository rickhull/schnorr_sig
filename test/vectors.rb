require 'schnorr_sig'
require 'csv'

ENV['NO_SECURERANDOM'] = '1'

path = File.join(__dir__, 'vectors.csv')
table = CSV.read(path, headers: true)

success = []
failure = []

table.each { |row|
  pk       = SchnorrSig.hex2bin row.fetch('public key')
  m        = SchnorrSig.hex2bin row.fetch('message')
  sig      = SchnorrSig.hex2bin row.fetch('signature')
  expected = row.fetch('verification result') == 'TRUE'

  result = begin
             SchnorrSig.verify?(pk, m, sig)
           rescue SchnorrSig::Error
             false
           end
  (result == expected ? success : failure) << row
  print '.'
}
puts

puts "Success: #{success.count}"
puts "Failure: #{failure.count}"

puts failure unless failure.empty?

# exit failure.count
