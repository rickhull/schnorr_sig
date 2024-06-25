module SchnorrSig
  module Nostr
    class Error < RuntimeError
    end

    class DeprecatedError < Error
    end

    class EncodingError < Error
    end

    class SizeError < Error
    end

    def self.typecheck!: (untyped val, Class cls) -> untyped
    def self.binary!: (untyped str, ?Integer? length) -> String
    def self.hex!: (untyped str, ?Integer? length) -> String

    JSON_OPTIONS: Hash[Symbol, bool | String | Integer]

    def self.parse: (String json) -> (Hash[untyped, untyped] | Array[untyped])
    def self.json: ((Hash[untyped, untyped] | Array[untyped]) object) -> String

    class User
      @name: String
      @about: String
      @picture: String
      @sk: String
      @pk: String

      attr_reader name: String
      attr_reader about: String
      attr_reader picture: String
      attr_reader sk: String
      attr_reader pk: String

      def initialize: (name: String, ?about: String, ?picture: String,
                       ?sk: String?, ?pk: String?) -> void

      def pubkey: () -> String
      def new_event: (String content, kind: Integer | Symbol) -> Event
      def sign: (Event event) -> String
      def text_note: (String content) -> Event
      def set_metadata: (?about: String?, ?picture: String?,
                         **untyped kwargs) -> Event
      alias profile set_metadata

      def contact_list: (Hash[String, Array[String]]) -> Event
      alias follows contact_list

      def encrypted_text_message: (String content) -> Event
      alias direct_msg encrypted_text_message
    end

    class Event
      class Error < RuntimeError
      end

      class KeyError < Error
      end

      class SignatureMissing < Error
      end

      KINDS: Hash[Symbol, Integer]

      def self.kind: ((Integer | Symbol) val) -> Integer
      def self.sign: (String msg, String secret_key) -> String

      @content: String
      @kind: Integer
      @pubkey: String
      @tags: Array[Array[String]]
      @created_at: Integer
      @digest: String?
      @signature: String?

      attr_reader content: String
      attr_reader kind: Integer
      attr_reader created_at: Integer
      attr_reader pubkey: String
      attr_reader signature: String?

      def initialize: (?String content,
                       pubkey: String,
                       ?kind: Integer | Symbol) -> void

      def serialize: () -> [0, String, Integer, Integer,
                            Array[Array[String]], String]
      def digest: (?memo: bool) -> String
      def id: () -> String
      def sign: (String secret_key) -> String
      def signed?: () -> bool
      def signed!: () -> bool
      def sig: () -> String
      def object_hash: () -> Hash[Symbol, untyped]
      def json_object: () -> String

      def add_tag: (String tag, String value, *String rest) ->
        Array[Array[String]]
      def ref_event: (String eid_hex, *String rest) -> Array[Array[String]]
      def ref_pubkey: (String pk_hex, *String rest) -> Array[Array[String]]
      def ref_replace: (*String rest, kind: Integer,
        ?pubkey: String?, ?pk: String?, ?d_tag: String) ->
        Array[Array[String]]
    end
  end
end
