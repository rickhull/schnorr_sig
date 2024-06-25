D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib/schnorr_sig/util.rb"
  check "lib/schnorr_sig/pure.rb"
  check "lib/schnorr_sig/nostr.rb"

  library "ecdsa_ext"
  library "digest"
  library "securerandom"
  library "json"

  # configure_code_diagnostics(D::Ruby.strict)
end
