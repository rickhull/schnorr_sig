require 'schnorr_sig/pure'
require 'schnorr_sig/fast'

include SchnorrSig

sk, pk = Pure.keypair  # or Fast.keypair

msg = 'hello world'
hsh = Fast.tagged_hash('message', msg)
raise("hash mismatch") if Pure.tagged_hash('message', msg) != hsh

puts "Message: #{msg}"
puts "Tagged Hash: #{Fast.bin2hex(hsh)}"
puts

sigp = Pure.sign(sk, hsh)
sigf = Fast.sign(sk, hsh)

puts "Pure Sig: #{Pure.bin2hex(sigp)}"
puts "Fast Sig: #{Fast.bin2hex(sigf)}"
puts

puts "Fast.verify?(Pure.sign): #{Fast.verify?(pk, hsh, sigp)}"
puts "Pure.verify?(Fast.sign): #{Pure.verify?(pk, hsh, sigf)}"
