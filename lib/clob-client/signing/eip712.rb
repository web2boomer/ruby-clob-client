# frozen_string_literal: true

module ClobClient
  module Signing
    module EIP712
      CLOB_DOMAIN_NAME = 'ClobAuthDomain'
      CLOB_VERSION = '1'
      MSG_TO_SIGN = 'This message attests that I control the given wallet'

      def self.prepend_zx(hex_string)
        return hex_string if hex_string.start_with?('0x')
        "0x#{hex_string}"
      end

      def self.get_clob_auth_domain(chain_id)
        # config = ClobClient::Config.get_contract_config(chain_id)
        { 
          name: CLOB_DOMAIN_NAME, 
          version: CLOB_VERSION, 
          chainId: chain_id,
          # verifyingContract: config.exchange
        }
      end

      def self.sign_clob_auth_message(signer, timestamp, nonce)
        domain = get_clob_auth_domain(signer.get_chain_id)

        clob_auth = ClobClient::Signing::ClobAuth.new(
          address: signer.address,
          timestamp: timestamp.to_s, 
          nonce: nonce.to_i,             
          message: MSG_TO_SIGN
        )

        # Strict EIP-712: sign the digest directly
        signable_data = clob_auth.signable_bytes(domain)
        signature = signer.sign(signable_data)
        signature = prepend_zx signature
        signature
      end
      
      def self.sign_order_message(signer, order_fields, domain = nil)
        domain ||= get_clob_auth_domain(signer.get_chain_id)
        order_struct = ClobClient::Signing::OrderStruct.new(**order_fields)
        signable_data = order_struct.signable_bytes(domain)
        order_struct_hash = ClobClient::Signing::Model.keccak256(signable_data)
        signature = signer.sign(order_struct_hash)
        signature = prepend_zx signature
        signature        
      end
    end
  end
end 