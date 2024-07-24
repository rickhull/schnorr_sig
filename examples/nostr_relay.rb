require 'schnorr_sig/nostr'

include SchnorrSig::Nostr

sk, pk = SchnorrSig.keypair
source = Source.new(pk: pk)

puts "Public key:"
puts source.pubkey
puts

msg = source.text_note('hello world')

puts "Created message:"
puts msg
puts

msg.sign(sk)

puts "Signed message:"
p msg
puts

# msg is ready for delivery
# relay receives JSON string
puts "Relay receives:"
puts msg.to_json
puts

# verify the signature
# if no errors raised, signature is verified
# decompose into fields (Ruby hash buckets)
hash = Event.verify(msg.to_json)
puts "Signature verified:"
p hash
puts

puts "Relay serialization:"
puts Event.serialize(hash)
puts

# send received json to the the destination
puts "Relay sends:"
puts msg.to_json
puts
