D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib/schnorr_sig.rb"
  check "lib/schnorr_sig/pure.rb"

  library "ecdsa_ext"
  library "digest"
  library "securerandom"
  library "json"

  # configure_code_diagnostics(D::Ruby.strict)
end
