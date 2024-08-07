require 'schnorr_sig/nostr'
require 'minitest/autorun'

include SchnorrSig

describe Nostr do
  describe "module functions" do
    it "asserts an expected string is actually a string" do
      expect { Nostr.string!(1234) }.must_raise SchnorrSig::TypeError
      expect(Nostr.string!('asdf')).must_equal 'asdf'
    end

    it "asserts an expected binary string is actually binary" do
      expect { Nostr.binary!('asdf') }.must_raise SchnorrSig::EncodingError
      expect(Nostr.binary!('asdf'.b)).must_equal 'asdf'.b
    end

    it "optionally asserts the length of an expected binary string" do
      expect { Nostr.binary!("\x00".b, 2) }.must_raise SchnorrSig::SizeError
      expect(Nostr.binary!("\x00".b, 1)).must_equal "\x00".b
    end

    it "asserts an expected hex string is not actually binary" do
      expect { Nostr.hex!('abcd'.b) }.must_raise SchnorrSig::EncodingError
      expect(Nostr.hex!('abcd')).must_equal 'abcd'
    end

    it "optionally asserts the length of an expected hex string" do
      expect { Nostr.hex!("00", 1) }.must_raise SchnorrSig::SizeError
      expect(Nostr.hex!("00", 2)).must_equal "00"
    end

    it "asserts an expected integer is actually an integer" do
      expect { Nostr.integer!("1") }.must_raise SchnorrSig::TypeError
      expect(Nostr.integer!(1234)).must_be_kind_of Integer
    end

    it "asserts an expected array is actually an array" do
      expect { Nostr.array!(Hash.new) }.must_raise SchnorrSig::TypeError
      expect(Nostr.array!([1,2,3,4])).must_be_kind_of Array
    end

    it "parses a JSON string to a Ruby object" do
      expect(Nostr.parse('{}')).must_equal Hash.new
      expect(Nostr.parse('[]')).must_equal Array.new
    end

    it "generates JSON from a Ruby hash or array" do
      expect(Nostr.json({})).must_equal '{}'
      expect(Nostr.json([])).must_equal '[]'
    end
  end

  describe Nostr::Event do
    E = Nostr::Event
    SK, PK = SchnorrSig.keypair

    describe "class functions" do
      it "determines the _kind_ integer from an integer or symbol" do
        # any integer except 2 is valid
        # only a few symbols are valid
        expect(E.kind(0)).must_equal 0
        expect(E.kind(:set_metadata)).must_equal 0
        expect(E.kind(1)).must_equal 1
        expect(E.kind(:text_note)).must_equal 1
        expect { E.kind(2) }.must_raise E::Error
        expect { E.kind(:recommend_server) }.must_raise E::Error
        expect(E.kind(:contact_list)).must_equal 3
        expect(E.kind(:encrypted_direct_message)).must_equal 4
        expect(E.kind(5)).must_equal 5
        expect { E.kind(:unknown) }.must_raise
      end
    end

    def new_event(msg = 'test')
      E.new(msg, pubkey: SchnorrSig.bin2hex(PK))
    end

    it "requires a message and a hex(64) pubkey to initialize" do
      expect { E.new('asdf') }.must_raise
      event = E.new('test event', pubkey: SchnorrSig.bin2hex(PK))
      expect(event).must_be_kind_of E
      expect(event.kind).must_equal 1
    end

    it "serializes to a Ruby array of length 6" do
      e = new_event()
      a = e.serialize
      expect(a).must_be_kind_of Array
      expect(a).wont_be_empty
      expect(a.length) == 6
    end

    it "converts the array[6] to JSON, then SHA256 for 32B digest" do
      e = new_event()
      d = e.digest
      expect(d).must_be_kind_of String
      expect(d.encoding).must_equal Encoding::BINARY
      expect(d.length).must_equal 32
    end

    it "converts the digest to 64B hex encoding for the _id_ field" do
      e = new_event()
      i = e.id
      expect(i).must_be_kind_of String
      expect(i.encoding).wont_equal Encoding::BINARY
      expect(i.length).must_equal 64
    end

    it "signs the event with any 32B secret key yielding 64B sig" do
      e = new_event()
      s = e.sign(SK)
      expect(s).must_be_kind_of String
      expect(s.encoding).must_equal Encoding::BINARY
      expect(s.length).must_equal 64
    end

    it "checks whether the event has been signed" do
      e = new_event()
      expect(e.signed?).must_equal false

      e.sign(SK)
      expect(e.signed?).must_equal true
    end

    it "provides sig() as 128B of hex" do
      e = new_event()
      e.sign(SK)
      sig = e.sig
      expect(sig).must_be_kind_of String
      expect(sig.encoding).wont_equal Encoding::BINARY
      expect(sig.length).must_equal 128
    end

    it "provides to_h() as a Ruby hash, suitable for JSON conversion" do
      e = new_event()
      h = e.to_h
      expect(h).must_be_kind_of Hash
      expect(h[:id]).must_be_kind_of String
      expect(h[:sig]).must_be_empty

      e.sign(SK)
      h = e.to_h
      expect(h).must_be_kind_of Hash
      expect(h).wont_be_empty
      expect(h.length).must_equal 7
      expect(h[:sig]).wont_be_empty
    end

    it "provides to_json() as a NIPS01 Event object, a string of JSON" do
      e = new_event()
      # expect { e.to_json }.must_raise E::SignatureMissing

      e.sign(SK)
      j = e.to_json

      # id + pubkey + sig == 256 bytes

      expect(j).must_be_kind_of String
      expect(j).wont_be_empty
      expect(j.encoding).wont_equal Encoding::BINARY
      expect(j.length).must_be :>, 256
    end
  end

  describe Nostr::Source do
    it "requires a public key" do
      pk = Random.bytes(32)
      u = Nostr::Source.new(pk: pk)
      expect(u).must_be_kind_of Nostr::Source

      pubkey = u.pubkey
      expect(pubkey).must_be_kind_of String
      expect(pubkey.encoding).wont_equal Encoding::BINARY
      expect(pubkey.length).must_equal 64

      pk = u.pk
      expect(pk).must_be_kind_of String
      expect(pk.encoding).must_equal Encoding::BINARY
      expect(pk.length).must_equal 32
    end
  end
end
