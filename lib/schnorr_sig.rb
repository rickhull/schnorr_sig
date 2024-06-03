if ENV['SCHNORR_SIG']&.downcase == 'fast'
  require 'schnorr_sig/fast'
else
  require 'schnorr_sig/pure'
end
