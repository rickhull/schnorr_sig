loaded = false

if ENV['SCHNORR_SIG']&.downcase == 'fast'
  begin
    require 'schnorr_sig/fast'
    SchnorrSig.extend SchnorrSig::Fast
    loaded = true
  rescue LoadError => e
    warn [e.class, e.message].join(': ')
  end
end

unless loaded
  require 'schnorr_sig/pure'
  SchnorrSig.extend SchnorrSig::Pure
end
