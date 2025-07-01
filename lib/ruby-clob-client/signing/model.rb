# frozen_string_literal: true

module RubyClobClient
  module Signing
    module Model
      # TODO: Port signing model logic from Python signing/model.py
    end

    class ClobAuth
      attr_accessor :address, :timestamp, :nonce, :message

      def initialize(address:, timestamp:, nonce:, message:)
        @address = address
        @timestamp = timestamp
        @nonce = nonce
        @message = message
      end

      def signable_bytes(domain)
        # TODO: Implement EIP712 struct serialization
        ''
      end
    end
  end
end 