require 'schnorr_sig/nostr'

include SchnorrSig::Nostr

sk, pk = SchnorrSig.keypair
source = Device.new(pk: pk)

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
json = msg.json_object
puts "Relay receives:"
puts json
puts

# verify the signature
# if no errors raised, signature is verified
# decompose into fields (Ruby hash buckets)
hash = Device.verify(json)
puts "Signature verified:"
p hash
puts

puts "Relay serialization:"
puts Device.serialize(hash)
puts

# send received json to the the destination
puts "Relay sends:"
puts json
puts