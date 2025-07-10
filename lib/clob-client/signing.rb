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

      def self.encode_uint8(val)
        Eth::Abi.encode("uint8", val)
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
      attr_accessor :maker, :taker, :token_id, :maker_amount, :taker_amount, :side, :fee_rate_bps, :nonce, :signer, :expiration, :signature_type, :salt

      def initialize(maker:, taker:, token_id:, maker_amount:, taker_amount:, side:, fee_rate_bps:, nonce:, signer:, expiration:, signature_type:, salt:)
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
        @salt = salt
      end

      TYPE_HASH = Model.keccak256("Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)")

      def signable_bytes(domain)
        # Encode fields in the correct order as per the Python reference
        salt_enc        = Model.encode_uint256(@salt)
        maker_enc       = Model.encode_address(@maker)
        signer_enc      = Model.encode_address(@signer)
        taker_enc       = Model.encode_address(@taker)
        token_id_enc    = Model.encode_uint256(@token_id)
        maker_amt_enc   = Model.encode_uint256(@maker_amount)
        taker_amt_enc   = Model.encode_uint256(@taker_amount)
        expiration_enc  = Model.encode_uint256(@expiration)
        nonce_enc       = Model.encode_uint256(@nonce)
        fee_bps_enc     = Model.encode_uint256(@fee_rate_bps)
        side_enc        = Model.encode_uint8(@side.to_i)  # uint8, not hashed string
        sig_type_enc    = Model.encode_uint8(@signature_type.to_i)  # uint8, not hashed string

        packed = TYPE_HASH + salt_enc + maker_enc + signer_enc + taker_enc +
                 token_id_enc + maker_amt_enc + taker_amt_enc + expiration_enc +
                 nonce_enc + fee_bps_enc + side_enc + sig_type_enc

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
      
      def self.sign_order_message(signer, order_fields, domain = nil)
        domain ||= get_clob_auth_domain(signer.get_chain_id)
        order_struct = ClobClient::Signing::OrderStruct.new(**order_fields)
        signable_data = order_struct.signable_bytes(domain)
        # signable_data is already the final EIP712 digest, no need to hash again
        signature = signer.sign(signable_data)
        signature = prepend_zx signature
        signature        
      end
    end
  end
end 