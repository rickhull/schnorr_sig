begin
  require 'schnorr_sig/fast'
  SchnorrSig.extend SchnorrSig::Fast
rescue LoadError
  require 'schnorr_sig/pure'
  SchnorrSig.extend SchnorrSig::Pure
end
