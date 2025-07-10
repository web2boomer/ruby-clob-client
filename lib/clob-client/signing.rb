# frozen_string_literal: true
require 'openssl'
require 'base64'
require 'eth'
require 'digest/keccak'

module ClobClient
  module Signing
    # === HMAC ===
    module HMAC
      def self.build_hmac_signature(secret, timestamp, method, request_path, body = nil)
        base64_secret = Base64.urlsafe_decode64(secret)
        normalized_body = body ? body : ""
        message = "#{timestamp}#{method.upcase}#{request_path}#{normalized_body}"
        hmac = OpenSSL::HMAC.digest('sha256', base64_secret, message.encode('UTF-8'))
        Base64.urlsafe_encode64(hmac)
      end
    end

    # === MODEL ===
    module Model
      def self.keccak256(data)
        Digest::Keccak.digest(data, 256)
      end

      def self.encode_uint256(val)
        Eth::Abi.encode("uint256", val)
      end

      def self.encode_address(addr)
        return "" unless addr
        Eth::Abi.encode("address", addr)
      end

      def self.encode_string(str)
        keccak256(str.to_s)
      end

      def self.domain_separator_hash(domain)
        if domain[:verifyingContract]
          type_hash     = encode_string("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
          name_hash     = encode_string(domain[:name])
          version_hash  = encode_string(domain[:version])
          chain_id_enc  = encode_uint256(domain[:chainId])
          contract_enc  = encode_address(domain[:verifyingContract])
          packed = type_hash + name_hash + version_hash + chain_id_enc + contract_enc
        else
          type_hash     = encode_string("EIP712Domain(string name,string version,uint256 chainId)")
          name_hash     = encode_string(domain[:name])
          version_hash  = encode_string(domain[:version])
          chain_id_enc  = encode_uint256(domain[:chainId])
          packed = type_hash + name_hash + version_hash + chain_id_enc
        end
        keccak256(packed)
      end

      def self.create_eip712_digest(domain_separator, struct_hash)
        to_sign = "\x19\x01" + domain_separator + struct_hash
        encode_string(to_sign)
      end
    end

    class ClobAuth
      attr_accessor :address, :timestamp, :nonce, :message

      def initialize(address:, timestamp:, nonce:, message:)
        @address = address
        @timestamp = timestamp
        @nonce = nonce
        @message = message
      end

      TYPE_HASH = Model.keccak256("ClobAuth(address address,string timestamp,uint256 nonce,string message)")

      def signable_bytes(domain)
        address_enc    = Model.encode_address(@address)
        timestamp_enc  = Model.encode_string(@timestamp.to_s)
        nonce_enc      = Model.encode_uint256(@nonce.to_i)
        message_enc    = Model.encode_string(@message)
        packed = TYPE_HASH + address_enc + timestamp_enc + nonce_enc + message_enc
        struct_hash = Model.keccak256(packed)
        domain_separator = Model.domain_separator_hash(domain)
        digest = Model.create_eip712_digest(domain_separator, struct_hash)
        digest
      end
    end

    class OrderStruct
      attr_accessor :maker, :taker, :token_id, :maker_amount, :taker_amount, :side, :fee_rate_bps, :nonce, :signer, :expiration, :signature_type

      def initialize(maker:, taker:, token_id:, maker_amount:, taker_amount:, side:, fee_rate_bps:, nonce:, signer:, expiration:, signature_type:)
        @maker = maker
        @taker = taker
        @token_id = token_id
        @maker_amount = maker_amount
        @taker_amount = taker_amount
        @side = side
        @fee_rate_bps = fee_rate_bps
        @nonce = nonce
        @signer = signer
        @expiration = expiration
        @signature_type = signature_type
      end

      TYPE_HASH = Model.keccak256("Order(address maker,address taker,address token_id,uint256 maker_amount,uint256 taker_amount,string side,uint256 fee_rate_bps,uint256 nonce,address signer,uint256 expiration,string signature_type)")

      def signable_bytes(domain)
        maker_enc       = Model.encode_address(@maker)
        taker_enc       = Model.encode_address(@taker)
        token_id_enc    = Model.encode_uint256(@token_id)
        maker_amt_enc   = Model.encode_uint256(@maker_amount)
        taker_amt_enc   = Model.encode_uint256(@taker_amount)
        side_hash       = Model.encode_string(@side)
        fee_bps_enc     = Model.encode_uint256(@fee_rate_bps)
        nonce_enc       = Model.encode_uint256(@nonce)
        signer_enc      = Model.encode_address(@signer)
        expiration_enc  = Model.encode_uint256(@expiration)
        sig_type_hash   = Model.encode_string(@signature_type)
        packed = TYPE_HASH + maker_enc + taker_enc + token_id_enc +
                 maker_amt_enc + taker_amt_enc + side_hash +
                 fee_bps_enc + nonce_enc + signer_enc +
                 expiration_enc + sig_type_hash
        struct_hash = Model.keccak256(packed)
        domain_separator = Model.domain_separator_hash(domain)
        Model.create_eip712_digest(domain_separator, struct_hash)
      end
    end

    # === EIP712 ===
    module EIP712
      CLOB_DOMAIN_NAME = 'ClobAuthDomain'
      CLOB_VERSION = '1'
      MSG_TO_SIGN = 'This message attests that I control the given wallet'

      def self.prepend_zx(hex_string)
        return hex_string if hex_string.start_with?('0x')
        "0x#{hex_string}"
      end

      def self.get_clob_auth_domain(chain_id)
        { 
          name: CLOB_DOMAIN_NAME, 
          version: CLOB_VERSION, 
          chainId: chain_id,
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
        signable_data = clob_auth.signable_bytes(domain)
        signature = signer.sign(signable_data)
        signature = prepend_zx signature
        signature
      end
      
      def self.sign_order_message(signer, order_fields)
        domain = get_clob_auth_domain(signer.get_chain_id)
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