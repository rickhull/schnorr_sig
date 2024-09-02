require 'schnorr_sig'
require 'csv'

ENV['NO_SECURERANDOM'] = '1'

path = File.join(__dir__, 'vectors.csv')
table = CSV.read(path, headers: true)

success = []
failure = []
skip    = []

table.each { |row|
  pk       = SchnorrSig.hex2bin row.fetch('public key')
  m        = SchnorrSig.hex2bin row.fetch('message')
  sig      = SchnorrSig.hex2bin row.fetch('signature')
  expected = row.fetch('verification result') == 'TRUE'

  result = begin
             SchnorrSig.soft_verify?(pk, m, sig)
           rescue SchnorrSig::SizeError
             skip << row
             next
           end

  if result == expected
    success << row
  else
    failure << row
  end
  print '.'
}
puts

puts "Success: #{success.count}"
puts "Failure: #{failure.count}"
puts "Skipped: #{skip.count}"

failure.each { |row| p row }
exit failure.count
