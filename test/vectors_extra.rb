require 'csv'

case ENV['SCHNORR']
when 'fast', 'FAST'
  require 'schnorr_sig/fast'
else
  require 'schnorr_sig'
end

path = File.join(__dir__, 'vectors.csv')
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

  pk_msg = nil
  sig_msg = nil
  verify_msg = nil

  # let's derive pk from sk
  if !sk.empty?
    pubkey = SchnorrSig.pubkey(sk)
    pk_msg = pubkey == pk ? "pk match" : "pk mismatch"

    calc_sig = SchnorrSig.sign(sk, m)
    sig_msg = calc_sig == sig ? "sig match" : "sig mismatch"
  else
    pk_msg = "sk empty"
    sig_msg = "sk empty"
  end

  result = begin
             SchnorrSig.verify?(pk, m, sig)
           rescue SchnorrSig::Error
             false
           end
  verify_msg = result == expected ? "verify match" : "verify mismatch"
  puts [index, pk_msg, sig_msg, verify_msg].join("\t")
  #  print '.'
}
puts

#puts "Success: #{success.count}"
#puts "Failure: #{failure.count}"

#puts failure unless failure.empty?

#exit failure.count
