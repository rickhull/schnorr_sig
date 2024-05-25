require 'csv'
require 'schnorr_sig'

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
  result   = row.fetch('verification result') == 'TRUE'

  begin
    Schnorr.verify(pk, m, sig)
    if result
      success << row
    else
      warn "index #{index} passed verification; expected failure"
      failure << row
    end
  rescue Schnorr::Error => e
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

puts failure unless failure.empty?

exit failure.count
