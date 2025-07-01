# frozen_string_literal: true

module RubyClobClient
  module Signing
    module EIP712
      CLOB_DOMAIN_NAME = 'ClobAuthDomain'
      CLOB_VERSION = '1'
      MSG_TO_SIGN = 'This message attests that I control the given wallet'

      def self.get_clob_auth_domain(chain_id)
        # TODO: Implement EIP712 domain struct
        { name: CLOB_DOMAIN_NAME, version: CLOB_VERSION, chainId: chain_id }
      end

      def self.sign_clob_auth_message(signer, timestamp, nonce)
        # TODO: Implement EIP712 signing logic
        'stub_signature'
      end
    end
  end
end 