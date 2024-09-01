require 'schnorr_sig/pure'

ENV['NO_SECURERANDOM'] = '1'

include SchnorrSig

msg = 'hello world'
hsh = Pure.tagged_hash('test', msg)

sk, pk = Pure.keypair
puts "Message: #{msg}"
puts "Hash: #{Pure.bin2hex(hsh)}"
puts "Secret key: #{Pure.bin2hex(sk)}"
puts "Public key: #{Pure.bin2hex(pk)}"
puts

sig = Pure.sign(sk, hsh)
puts "Signature: #{Pure.bin2hex(sig)}"
puts "Encoding: #{sig.encoding}"
puts "Length: #{sig.length}"
puts "Verified: #{Pure.verify?(pk, hsh, sig)}"
