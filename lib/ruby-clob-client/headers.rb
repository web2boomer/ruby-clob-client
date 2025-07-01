# frozen_string_literal: true
require 'time'

module RubyClobClient
  module Headers
    POLY_ADDRESS = 'POLY_ADDRESS'
    POLY_SIGNATURE = 'POLY_SIGNATURE'
    POLY_TIMESTAMP = 'POLY_TIMESTAMP'
    POLY_NONCE = 'POLY_NONCE'
    POLY_API_KEY = 'POLY_API_KEY'
    POLY_PASSPHRASE = 'POLY_PASSPHRASE'

    def self.create_level_1_headers(signer, nonce = nil)
      timestamp = Time.now.to_i
      n = nonce || 0
      signature = 'stub_signature' # TODO: Implement EIP712 signing
      {
        POLY_ADDRESS => signer.address,
        POLY_SIGNATURE => signature,
        POLY_TIMESTAMP => timestamp.to_s,
        POLY_NONCE => n.to_s
      }
    end

    def self.create_level_2_headers(signer, creds, request_args)
      timestamp = Time.now.to_i
      hmac_sig = 'stub_hmac' # TODO: Implement HMAC signing
      {
        POLY_ADDRESS => signer.address,
        POLY_SIGNATURE => hmac_sig,
        POLY_TIMESTAMP => timestamp.to_s,
        POLY_API_KEY => creds.api_key,
        POLY_PASSPHRASE => creds.api_passphrase
      }
    end
  end
end 