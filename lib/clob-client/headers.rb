# frozen_string_literal: true
require 'time'
require_relative 'signing/eip712'
require_relative 'signing/hmac'

module ClobClient
  module Headers
    POLY_ADDRESS = 'POLY_ADDRESS'
    POLY_SIGNATURE = 'POLY_SIGNATURE'
    POLY_TIMESTAMP = 'POLY_TIMESTAMP'
    POLY_NONCE = 'POLY_NONCE'
    POLY_API_KEY = 'POLY_API_KEY'
    POLY_PASSPHRASE = 'POLY_PASSPHRASE'

    def self.create_level_1_headers(signer, nonce = nil)
      # timestamp = Time.now.to_i
      timestamp = 1751978273
      signature = RubyClobClient::Signing::EIP712.sign_clob_auth_message(signer, timestamp, nonce)
      # signature = '0x4e0d98e2f711669895ad08dd55bb2d00028f3235cae78e53ff6bc6c6bee2e9bc2c36659ead0968dea800f0ef3f6f16535f7dd7a4ae4c7f222c17d88ece88b3191c'
      {
        POLY_ADDRESS => signer.address,
        POLY_SIGNATURE => signature,
        POLY_TIMESTAMP => timestamp.to_s,
        POLY_NONCE => nonce.to_s
      }
    end

    def self.create_level_2_headers(signer, creds, request_args)
      timestamp = Time.now.to_i
      timestamp = 1751932804
      hmac_sig = RubyClobClient::Signing::HMAC.build_hmac_signature(
        creds.api_secret,
        timestamp.to_s,
        request_args.method,
        request_args.request_path,
        request_args.body
      )
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