require 'schnorr_sig'
require 'csv'

ENV['NO_SECURERANDOM'] = '1'

path = File.join(__dir__, 'vectors.csv')
table = CSV.read(path, headers: true)

table.each { |row|
  sk       = SchnorrSig.hex2bin row.fetch('secret key')
  pk       = SchnorrSig.hex2bin row.fetch('public key')
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
      sig_msg = (calc_sig == sig) ? "sig match" : "sig mismatch"
    rescue SchnorrSig::SpecError
      sig_msg = "sig error"
    end
  end

  if sig_msg != "sig error"
    begin
      result = SchnorrSig.soft_verify?(pk, m, sig)
      verify_msg = (result == expected) ? "verify match" : "verify mismatch"
    rescue SchnorrSig::SpecError => e
      verify_msg = "verify error"
    end
  else
    verify_msg = "sig error"
  end
  puts [index, pk_msg, sig_msg, verify_msg, comment].join("\t")
}
puts
