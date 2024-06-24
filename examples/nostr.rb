require 'schnorr_sig/nostr'

include SchnorrSig

# keypair will be generated
marge = Nostr::User.new(name: 'Marge')
hello = marge.text_note('Good morning, Homie')

puts "Marge Simpson: hello world"
puts

puts "Serialized"
p hello.serialize
puts

marge.sign(hello)

puts "Event Object"
puts hello.json_object
puts

#####

# use our own secret key; pubkey will be generated
homer = Nostr::User.new(name: 'Homer', about: 'Homer Jay Simpson',
                        sk: Random.bytes(32))
response = homer.text_note('Good morning, Marge')
response.ref_event(hello.id)

puts
puts "Homer: hello back"
puts

puts "Serialized"
p response.serialize
puts

homer.sign(response)

puts "Event Object"
puts response.json_object
puts

#####

puts
puts "Homer: love letter"
puts

love_letter = homer.text_note("I love you Marge.\nLove, Homie")
love_letter.ref_pubkey(SchnorrSig.bin2hex(marge.pk))

puts "Serialized"
p love_letter.serialize
puts

homer.sign(love_letter)

puts "Event Object"
puts love_letter.json_object
puts

#####

puts
puts "Bart uploads his profile"
puts


# we'll "bring our own" keypair
sk, pk = SchnorrSig.keypair
bart = Nostr::User.new(name: 'Bart',
                       about: 'Bartholomew Jojo Simpson',
                       picture: 'https://upload.wikimedia.org/wikipedia/en/a/aa/Bart_Simpson_200px.png',
                       sk: sk, pk: pk)
profile = bart.set_metadata

puts "Serialized"
p profile.serialize
puts

bart.sign(profile)

puts "Event Object"
puts profile.json_object
puts

puts "Profile Content"
puts profile.content
puts

#####

puts
puts "lisa follows her family"
puts

lisa = Nostr::User.new(name: 'Lisa')
# keys = [marge.pk, homer.pk, bart.pk
following = lisa.contact_list({ marge.pubkey => [],
                                homer.pubkey => [],
                                bart.pubkey  => [], })

puts "Serialized"
p following.serialize
puts

lisa.sign(following)

puts "Event Object"
puts following.json_object
