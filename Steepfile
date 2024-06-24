D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib/schnorr_sig/pure.rb"
  check "lib/schnorr_sig/util.rb"

  library "ecdsa_ext"
  library "digest"
  library "securerandom"

  # configure_code_diagnostics(D::Ruby.strict)
end
