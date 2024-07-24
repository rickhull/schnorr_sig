require 'schnorr_sig'
require 'json'
require 'digest'

# this implements most/all of NIP-01, which is the only _required_ spec
# see https://github.com/nostr-protocol/nips/blob/master/01.md

module SchnorrSig
  module Nostr
    # raise SchnorrSig::TypeError or return str
    def self.string!(str)
      SchnorrSig.string!(str) and str
    end

    # raise SchnorrSig::TypeError or return int
    def self.integer!(int)
      SchnorrSig.integer!(int) and int
    end

    # raise SchnorrSig::TypeError or SchnorrSig::SizeError or return ary
    def self.array!(ary, length = nil)
      raise(TypeError, ary.class) unless ary.is_a?(Array)
      raise(SizeError, ary.length) if length and length != ary.length
      ary
    end

    # raise (EncodingError, SizeError) or return str
    def self.binary!(str, length = nil)
      SchnorrSig.string!(str)
      raise(EncodingError, str.encoding) if str.encoding != Encoding::BINARY
      raise(SizeError, str.length) if length and length != str.length
      str
    end

    # raise or return str
    def self.hex!(str, length = nil)
      SchnorrSig.string!(str)
      raise(EncodingError, str.encoding) if str.encoding == Encoding::BINARY
      raise(SizeError, str.length) if length and length != str.length
      str
    end

    # per NIP-01
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

    class Event
      class Error < RuntimeError; end
      class FrozenError < Error; end
      class IdCheck < Error; end
      class SignatureCheck < Error; end

      # id: 64 hex chars (32B)
      # pubkey: 64 hex chars (32B)
      # created_at: unix seconds
      # kind: 0..65535
      # tags: []
      # content: any string
      # sig: 128 hex chars (64B)

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
      # 1a. generate content: String
      # 1b. set kind: Integer
      # 1c. set tags: Array
      # 2. timestamp: Integer
      # 3. generate id: SHA256
      # 4. sign(sk): 64B

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
          raise(Error, "Deprecated: kind value 2")
        when Integer
          val
        else
          KINDS.fetch(val)
        end
      end

      # Array[Array[String]]
      def self.tags!(ary)
        Nostr.array!(ary).each { |a|
          Nostr.array!(a).each { |s| Nostr.string! s }
        }
        ary
      end

      # deconstruct and typecheck, return a ruby hash
      # this should correspond directly to Event#to_h
      def self.hash(json_str)
        j = Nostr.parse(json_str)
        raise(Error, "Hash expected: #{j.inspect}") unless j.is_a? Hash
        { id:      Nostr.string!(j.fetch("id")),
          pubkey:  Nostr.string!(j.fetch("pubkey")),
          kind:                  j.fetch("kind"),
          content: Nostr.string!(j.fetch("content")),
          tags:      Event.tags!(j.fetch("tags")),
          created_at:            j.fetch("created_at"),
          sig:     Nostr.string!(j.fetch("sig")), }
      end

      # (re-)create the JSON array serialization
      # this should correspond directly to Event#to_s (JSON array)
      def self.serialize(hash)
        Nostr.json([0,
                    hash.fetch(:pubkey),
                    hash.fetch(:created_at),
                    hash.fetch(:kind),
                    hash.fetch(:tags),
                    hash.fetch(:content),])
      end

      # validate the id (optional) and signature
      def self.verify(json_str, check_id: true)
        h = self.hash(json_str)

        # check the id
        id = SchnorrSig.hex2bin(h.fetch(:id))
        if check_id and id != Digest::SHA256.digest(self.serialize(h))
          raise(IdCheck, h.fetch(:id))
        end

        # verify the signature
        unless SchnorrSig.verify?(SchnorrSig.hex2bin(h.fetch(:pubkey)),
                                  id,
                                  SchnorrSig.hex2bin(h.fetch(:sig)))
          raise(SignatureCheck, h[:sig])
        end
        h
      end

      attr_reader :content, :kind, :created_at, :pubkey, :signature

      def initialize(content = '', kind: :text_note, pubkey:)
        @content = Nostr.string!(content)
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

      # JSON string, the array from serialize() above
      def to_s
        Nostr.json(self.serialize)
      end

      # assign @digest, return 32 bytes binary
      def digest(memo: true)
        return @digest.to_s if memo and @digest

        # we are creating or recreating the event
        @created_at = nil
        @digest = Digest::SHA256.digest(self.to_s)
      end

      # return 64 bytes of hexadecimal, ASCII encoded
      def id
        SchnorrSig.bin2hex self.digest(memo: true)
      end

      # return a Ruby hash, suitable for JSON conversion to NIPS01 Event object
      def to_h
        { id: self.id,
          pubkey: @pubkey,
          created_at: @created_at,
          kind: @kind,
          tags: @tags,
          content: @content,
          sig: self.sig.to_s }
      end

      def to_json
        signed? ? Nostr.json(self.to_h) : self.to_s
      end

      # assign @signature, return 64 bytes binary
      # signing will reset created_at and thus the digest / id
      def sign(secret_key)
        @signature = SchnorrSig.sign(Nostr.binary!(secret_key, 32),
                                     self.digest(memo: false))
      end

      def signed?
        !!@signature
      end

      # return 128 bytes of hexadecimal, ASCII encoded
      def sig
        @signature and SchnorrSig.bin2hex(@signature.to_s)
      end

      # add an array of 2+ strings to @tags
      def add_tag(tag, value, *rest)
        raise(FrozenError) if signed?
        @digest = nil # invalidate any prior digest
        @tags.push([Nostr.string!(tag), Nostr.string!(value)] +
                   rest.each { |s| Nostr.string!(s) })
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
        pubkey ||= SchnorrSig.bin2hex(pk.to_s)
        val = [Event.kind(kind), Nostr.hex!(pubkey, 64), d_tag].join(':')
        add_tag('a', val, *rest)
      end
    end

    #####################
    #
    # A Source holds a public key and creates Events.
    #

    class Source
      attr_reader :pubkey

      def initialize(pubkey: nil, pk: nil)
        if pubkey
          @pubkey = Nostr.hex!(pubkey, 64)
        elsif pk
          @pubkey = SchnorrSig.bin2hex(Nostr.binary!(pk, 32))
        else
          raise "public key is required"
        end
      end

      def pk
        SchnorrSig.hex2bin @pubkey
      end

      # returns an Event, kind: 1, text_note
      def text_note(content)
        Event.new(Nostr.string!(content), kind: :text_note, pubkey: @pubkey)
      end

      # Input
      #   name: string
      #   about: string
      #   picture: string, URL
      # Output
      #   Event
      #     kind: 0, set_metadata
      #     content: {
      #       name: <username>, about: <string>, picture: <url, string>
      #     }
      def set_metadata(**kwargs)
        Nostr.string!(kwargs.fetch(:name))
        Nostr.string!(kwargs.fetch(:about))
        Nostr.string!(kwargs.fetch(:picture))

        Event.new(Nostr.json(kwargs), kind: :set_metadata, pubkey: @pubkey)
      end
      alias_method :profile, :set_metadata

      # Input
      #   pubkey_hsh: a ruby hash of the form
      #     "deadbeef1234abcdef" => ["wss://alicerelay.com/", "alice"]
      def contact_list(pubkey_hsh)
        list = Event.new('', kind: :contact_list, pubkey: @pubkey)
        pubkey_hsh.each { |pubkey, ary|
          list.ref_pubkey(Nostr.hex!(pubkey, 64), *Nostr.array!(ary))
        }
        list
      end
      alias_method :follows, :contact_list

      def encrypted_text_message(content)
        Event.new(Nostr.string!(content),
                  kind: :encrypted_text_message,
                  pubkey: @pubkey)
      end
      alias_method :direct_msg, :encrypted_text_message
    end
  end
end
