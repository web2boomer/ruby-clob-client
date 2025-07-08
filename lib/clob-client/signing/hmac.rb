# frozen_string_literal: true
require 'openssl'
require 'base64'

module ClobClient
  module Signing
    module HMAC
      def self.build_hmac_signature(secret, timestamp, method, request_path, body = nil)
        base64_secret = Base64.urlsafe_decode64(secret)
        message = "#{timestamp}#{method}#{request_path}"
        message += body.to_s.gsub("'", '"') if body
        hmac = OpenSSL::HMAC.digest('sha256', base64_secret, message.encode('UTF-8'))
        Base64.urlsafe_encode64(hmac)
      end
    end
  end
end 