require 'schnorr_sig'
require 'json'
require 'digest'

module SchnorrSig
  module Nostr
    class Error < RuntimeError; end
    class DeprecatedError < Error; end
    class EncodingError < Error; end
    class SizeError < Error; end

    # raise or return val
    def self.typecheck!(val, cls)
      raise(TypeError, "#{cls} : #{val.inspect}") unless val.is_a? cls
      val
    end

    # raise or return str
    def self.binary!(str, length = nil)
      Nostr.typecheck!(str, String)
      raise(EncodingError, str.encoding) if str.encoding != Encoding::BINARY
      if length and length != str.bytesize
        raise(SizeError, "#{length} : #{str.bytesize}")
      end
      str
    end

    # raise or return str
    def self.hex!(str, length = nil)
      Nostr.typecheck!(str, String)
      raise(EncodingError, str.encoding) if str.encoding == Encoding::BINARY
      if length and length != str.bytesize
        raise(SizeError, "#{length} : #{str.bytesize}")
      end
      str
    end

    JSON_OPTIONS = {
      allow_nan: false,
      max_nesting: 3,
      script_safe: false,
      ascii_only: false,
      array_nl: '',
      object_nl: '',
      indent: '',
      space: '',
      space_before: '',
    }

    # return a ruby object, likely hash or array
    def self.parse(json)
      JSON.parse(json, **JSON_OPTIONS)
    end

    # convert a ruby object, likely hash or array, return a string of JSON
    def self.json(object)
      JSON.generate(object, **JSON_OPTIONS)
    end

    # this class stores user profile info, keys, and is responsible for
    # creating events (messages, etc)
    class User
      attr_reader :name, :about, :picture, :sk, :pk

      def initialize(name:, about: '', picture: '', sk: nil, pk: nil)
        @name = Nostr.typecheck!(name, String)
        @about = Nostr.typecheck!(about, String)
        @picture = Nostr.typecheck!(picture, String)
        if sk
          @sk = Nostr.binary!(sk, 32)
          @pk = pk.nil? ? SchnorrSig.pubkey(@sk) : Nostr.binary!(pk, 32)
        else
          @sk, @pk = SchnorrSig.keypair
        end
      end

      def pubkey
        SchnorrSig.bin2hex @pk
      end

      # returns an Event
      def new_event(content, kind:)
        Event.new(content, kind: kind, pubkey: self.pubkey)
      end

      # returns 64 bytes binary
      def sign(event)
        event.sign(@sk)
      end

      # returns an Event, kind: 1, text_note
      def text_note(content)
        new_event(content, kind: :text_note)
      end

      # Input
      #   (about: string)
      #   (picture: string)
      # Output
      #   Event
      #     kind: 0, set_metadata
      #     content: {
      #       name: <username>, about: <string>, picture: <url, string>
      #     }
      def set_metadata(about: nil, picture: nil, **kwargs)
        @about = about if about and about != @about
        @picture = picture if picture and picture != @picture
        hash = kwargs.merge({ name:    @name,
                              about:   Nostr.typecheck!(@about, String),
                              picture: Nostr.typecheck!(@picture, String), })

        new_event(Nostr.json(hash), kind: :set_metadata)
      end
      alias_method :profile, :set_metadata

      # Input
      #   pubkey_hsh: a ruby hash of the form
      #     "deadbeef1234abcdef" => ["wss://alicerelay.com/", "alice"]
      def contact_list(pubkey_hsh)
        list = new_event('', kind: :contact_list)
        pubkey_hsh.each { |pubkey, ary|
          list.ref_pubkey(Nostr.hex!(pubkey, 64), *(ary or Array.new))
        }
        list
      end
      alias_method :follows, :contact_list

      def encrypted_text_message(content)
        new_event(content, kind: :encrypted_text_message)
      end
      alias_method :direct_msg, :encrypted_text_message
    end

    class Event
      class Error < RuntimeError; end
      class KeyError < Error; end
      class SignatureMissing < Error; end

      # id: 32 bytes (hex = 64)
      # pubkey: 32 bytes (hex = 64)
      # created_at: unix seconds
      # kind: 0..65535
      # tags: []
      # content: "hello world"
      # sig: 64 bytes (hex = 128)

      # the id is a SHA256 of the serialized event:
      # [
      #   0,
      #   <pubkey, lowercase hex>,
      #   <created at>,
      #   <kind>,
      #   <tags>,
      #   <content>
      # ]

      # 1. using public key:
      # 1a. generate content: "hello world"
      # 1b. set kind
      # 1c. set tags
      # 2. timestamp
      # 3. generate id
      #
      # 4. sign (requires id and priv key)

      KINDS = {
        set_metadata: 0,
        text_note: 1,
        # recommend_server: 2, deprecated
        contact_list: 3,
        encrypted_direct_message: 4,
      }

      def self.kind(val)
        case val
        when 2, :recommend_server
          raise(DeprecatedError, "kind value 2")
        when Integer
          val
        else
          KINDS.fetch(val)
        end
      end

      # returns 64 byte binary string
      def self.sign(msg, secret_key)
        SchnorrSig.sign(secret_key, msg)
      end

      attr_reader :content, :kind, :created_at, :pubkey, :signature

      def initialize(content = '', kind: :text_note, pubkey:)
        @content = Nostr.typecheck!(content, String)
        @kind = Event.kind(kind)
        @pubkey = Nostr.hex!(pubkey, 64)
        @tags = []
        @created_at = nil
        @digest = nil
        @signature = nil
      end

      # conditionally initialize @created_at, return ruby array
      def serialize
        [0,
         @pubkey,
         @created_at ||= Time.now.to_i,
         @kind,
         @tags,
         @content]
      end

      # assign @digest, return 32 bytes binary
      def digest(memo: true)
        return @digest if memo and @digest # steep:ignore

        # we are creating or recreating the event
        @created_at = nil
        @digest = Digest::SHA256.digest Nostr.json(self.serialize)
      end

      # return 64 bytes of hexadecimal, ASCII encoded
      def id
        SchnorrSig.bin2hex self.digest(memo: true)
      end

      # assign @signature, return 64 bytes binary
      def sign(secret_key)
        Nostr.binary!(secret_key, 32)
        @signature = SchnorrSig.sign(secret_key, self.digest(memo: false))
      end

      def signed?
        @signature and @signature.bytesize == 64 # steep:ignore
      end

      def signed!
        self.signed? or raise(SignatureMissing)
      end

      # steep:ignore:start
      # return 128 bytes of hexadecimal, ASCII encoded
      def sig
        self.signed! and SchnorrSig.bin2hex(@signature)
      end

      # return a Ruby hash, suitable for JSON conversion to NIPS01 Event object
      def object_hash
        self.signed! and {
          id: self.id,
          pubkey: @pubkey,
          created_at: @created_at,
          kind: @kind,
          tags: @tags,
          content: @content,
          sig: self.sig,
        }
      end
      # steep:ignore:end

      def json_object
        Nostr.json(self.object_hash)
      end

      # add an array of 2+ strings to @tags
      def add_tag(tag, value, *rest)
        @digest = nil # invalidate any prior digest
        @tags.push([Nostr.typecheck!(tag, String),
                    Nostr.typecheck!(value, String)] +
                   rest.each { |s| Nostr.typecheck!(s, String) })
      end

      # add an event tag based on event id, hex encoded
      def ref_event(eid_hex, *rest)
        add_tag('e', Nostr.hex!(eid_hex, 64), *rest)
      end

      # add a pubkey tag based on pubkey, 64 bytes hex encoded
      def ref_pubkey(pk_hex, *rest)
        add_tag('p', Nostr.hex!(pk_hex, 64), *rest)
      end

      # kind: and one of [pubkey:, pk:] required
      def ref_replace(*rest, kind:, pubkey: nil, pk: nil, d_tag: '')
        raise(ArgumentError, "public key required") if pubkey.nil? and pk.nil?
        pubkey ||= SchnorrSig.bin2hex(pk) # steep:ignore
        val = [Event.kind(kind), Nostr.hex!(pubkey, 64), d_tag].join(':')
        add_tag('a', val, *rest)
      end
    end
  end
end
