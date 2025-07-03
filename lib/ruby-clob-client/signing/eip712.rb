# frozen_string_literal: true

module RubyClobClient
  module Signing
    module EIP712
      CLOB_DOMAIN_NAME = 'ClobAuthDomain'
      CLOB_VERSION = '1'
      MSG_TO_SIGN = 'This message attests that I control the given wallet'

      def self.get_clob_auth_domain(chain_id)
        { name: CLOB_DOMAIN_NAME, version: CLOB_VERSION, chainId: chain_id }
      end

      def self.sign_clob_auth_message(signer, timestamp, nonce)
        domain = get_clob_auth_domain(signer.chain_id)
        clob_auth = RubyClobClient::Signing::ClobAuth.new(
          address: signer.address,
          timestamp: timestamp.to_i,  
          nonce: nonce.to_i,             
          message: MSG_TO_SIGN
        )
        ap clob_auth
        hash = clob_auth.signable_bytes(domain)  
        # p "hash is #{hash}"
        signature = signer.sign(hash)  
        # p "signature is #{signature}"
        signature
      end

      def self.sign_order_message(signer, order_fields)
        domain = get_clob_auth_domain(signer.chain_id)
        order_struct = RubyClobClient::Signing::Model::OrderStruct.new(**order_fields)
        hash = order_struct.signable_bytes(domain)
        signer.sign(hash.unpack1('H*').prepend('0x'))
      end
    end
  end
end 