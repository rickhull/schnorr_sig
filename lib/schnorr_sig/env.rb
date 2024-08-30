# never require both schnorr_sig/pure and schnorr_sig/fast
if ENV['SCHNORR_SIG']&.downcase == 'fast'
  begin
    require 'schnorr_sig/fast'
  rescue LoadError
    warn "LoadError: schnorr_sig/fast cannot be loaded"
    require 'schnorr_sig/pure'
  end
else
  require 'schnorr_sig/pure'
end
