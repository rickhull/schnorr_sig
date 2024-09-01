require 'schnorr_sig'
require 'csv'

ENV['NO_SECURERANDOM'] = '1'

path = File.join(__dir__, 'vectors.csv')
table = CSV.read(path, headers: true)

table.each { |row|
  sk       = SchnorrSig.hex2bin row.fetch('secret key')
  pk       = SchnorrSig.hex2bin row.fetch('public key')
  #aux_rand = SchnorrSig.hex2bin row.fetch('aux_rand')
  m        = SchnorrSig.hex2bin row.fetch('message')
  sig      = SchnorrSig.hex2bin row.fetch('signature')

  index    = row.fetch('index')
  comment  = row.fetch('comment')
  expected = row.fetch('verification result') == 'TRUE'

  pk_msg = nil
  sig_msg = nil
  verify_msg = nil

  if sk.empty?
    pk_msg = "sk empty"
    sig_msg = "sk empty"
  else
    # let's derive pk from sk
    pubkey = SchnorrSig.pubkey(sk)
    pk_msg = (pubkey == pk) ? "pk match" : "pk mismatch"

    # calculate a signature
    begin
      calc_sig = SchnorrSig.sign(sk, m)
    rescue SchnorrSig::Error
      calc_sig = "sig error"
    end
    sig_msg = (calc_sig == sig) ? "sig match" : "sig mismatch"
  end

  result = begin
             SchnorrSig.verify?(pk, m, sig)
           rescue SchnorrSig::Error
             false
           end
  verify_msg = (result == expected) ? "verify match" : "verify mismatch"
  puts [index, pk_msg, sig_msg, verify_msg, comment].join("\t")
}
puts
