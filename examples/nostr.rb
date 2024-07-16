require 'schnorr_sig/nostr'

include SchnorrSig

pubkeys = {}

# generate keypair
marge_sk, pk = SchnorrSig.keypair

# initiate a session
marge = Nostr::Session.new(pk: pk)

# create a message
hello = marge.text_note('Good morning, Homie')

puts "Marge Simpson: hello world"
puts

puts "Serialized"
p hello.serialize
puts

# sign the message
hello.sign(marge_sk)

puts "Event Object"
puts hello.json_object
puts

#####

# use our own secret key; generate the public key
homer_sk = Random.bytes(32)
pk = SchnorrSig.pubkey(homer_sk)

# initiate a session
homer = Nostr::Session.new(pk: pk)

# create a message
response = homer.text_note('Good morning, Marge')

# reference an earlier message
response.ref_event(hello.id)

puts
puts "Homer: hello back, private key, ref prior event"
puts

puts "Serialized"
p response.serialize
puts

response.sign(homer_sk)

puts "Event Object"
puts response.json_object
puts

#####

maggie_sk, pk = SchnorrSig.keypair
maggie = Nostr::Session.new(pk: pk)

puts
puts "Maggie: love letter, ref Marge's pubkey"
puts

love_letter = maggie.text_note("Dear Mom,\nYou're the best.\nLove, Maggie")
love_letter.ref_pubkey(marge.pubkey)

puts "Serialized"
p love_letter.serialize
puts

love_letter.sign(maggie_sk)

puts "Event Object"
puts love_letter.json_object
puts

#####

puts
puts "Bart uploads his profile"
puts


bart_sk, bart_pk = SchnorrSig.keypair
bart = Nostr::Session.new(pk: pk)
profile = bart.set_metadata(name: 'Bart',
                            about: 'Bartholomew Jojo Simpson',
                            picture: 'https://upload.wikimedia.org' +
                            '/wikipedia/en/a/aa/Bart_Simpson_200px.png')

puts "Serialized"
p profile.serialize
puts

profile.sign(bart_sk)

puts "Event Object"
puts profile.json_object
puts

puts "Profile Content"
puts profile.content
puts

#####

puts
puts "Lisa follows her family"
puts

lisa_sk, pk = SchnorrSig.keypair
lisa = Nostr::Session.new(pk: pk)

pubkey_hsh = {
  marge.pubkey => ["wss://thesimpsons.com/", "marge"],
  homer.pubkey => ["wss://thesimpsons.com/", "homer"],
  bart.pubkey => ["wss://thesimpsons.com/", "bart"],
  maggie.pubkey => ["wss://thesimpsons.com/", "maggie"],
}

following = lisa.contact_list(pubkey_hsh)

puts "Serialized"
p following.serialize
puts

following.sign(lisa_sk)

puts "Event Object"
puts following.json_object
