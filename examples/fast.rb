require 'schnorr_sig/fast'

ENV['NO_SECURERANDOM'] = '1'

include SchnorrSig

msg = 'hello world'
hsh = Fast.tagged_hash('test', msg)

sk, pk = Fast.keypair
puts "Message: #{msg}"
puts "Hash: #{Fast.bin2hex(hsh)}"
puts "Secret key: #{Fast.bin2hex(sk)}"
puts "Public key: #{Fast.bin2hex(pk)}"
puts

sig = Fast.sign(sk, hsh)
puts "Signature: #{Fast.bin2hex(sig)}"
puts "Encoding: #{sig.encoding}"
puts "Length: #{sig.length}"
puts "Verified: #{Fast.verify?(pk, hsh, sig)}"
