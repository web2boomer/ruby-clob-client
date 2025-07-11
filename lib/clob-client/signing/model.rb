# frozen_string_literal: true

require 'eth'
require 'digest/keccak'

module ClobClient
  module Signing
    module Model
      def self.keccak256(data)
        Digest::Keccak.digest(data, 256)
      end

      # Use eth.rb for ABI-encoded uint256 (32-byte)
      def self.encode_uint256(val)
        Eth::Abi.encode("uint256", val)
      end

      # Use eth.rb for ABI-encoded uint8 (1-byte padded to 32 bytes)
      def self.encode_uint8(val)
        Eth::Abi.encode("uint8", val)
      end

      # Use eth.rb for ABI-encoded address (20-byte padded to 32 bytes)
      def self.encode_address(addr)
        return "" unless addr
        Eth::Abi.encode("address", addr)
      end

      # For strings, we follow the EIP-712 rule of keccak256(utf8_bytes)
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

      # This method should match the logic in py_clob_client/signing/eip712.py:ClobAuth.signable_bytes
      # That is: keccak256(type_hash ++ encode_address ++ encode_string(timestamp) ++ encode_uint256(nonce) ++ encode_string(message))
      # and then the struct_hash is used with the domain separator for the EIP-712 digest.
      def signable_bytes(domain)
        # 1. Encode each field as per EIP-712 rules
        address_enc    = Model.encode_address(@address)
        timestamp_enc  = Model.encode_string(@timestamp.to_s)
        nonce_enc      = Model.encode_uint256(@nonce.to_i)
        message_enc    = Model.encode_string(@message)

        # 2. Pack fields in order: type_hash ++ address ++ timestamp ++ nonce ++ message
        packed = TYPE_HASH + address_enc + timestamp_enc + nonce_enc + message_enc

        # 3. Hash the packed struct to get struct_hash
        struct_hash = Model.keccak256(packed)

        # 4. Compute domain separator
        domain_separator = Model.domain_separator_hash(domain)

        # 5. Compute the EIP-712 digest
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
        puts "OrderStruct values before encoding:"
        puts "  salt: #{@salt.inspect}"
        puts "  maker: #{@maker.inspect}"
        puts "  signer: #{@signer.inspect}"
        puts "  taker: #{@taker.inspect}"
        puts "  token_id: #{@token_id.inspect}"
        puts "  maker_amount: #{@maker_amount.inspect}"
        puts "  taker_amount: #{@taker_amount.inspect}"
        puts "  expiration: #{@expiration.inspect}"
        puts "  nonce: #{@nonce.inspect}"
        puts "  fee_rate_bps: #{@fee_rate_bps.inspect}"
        puts "  side: #{@side.inspect}"
        puts "  signature_type: #{@signature_type.inspect}"

        # Encode fields in the correct order as per the TYPE_HASH
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
        side_enc        = Model.encode_uint8(@side.to_i)  # Convert to uint8
        sig_type_enc    = Model.encode_uint8(@signature_type.to_i)  # Convert to uint8

        packed = TYPE_HASH + salt_enc + maker_enc + signer_enc + taker_enc +
                 token_id_enc + maker_amt_enc + taker_amt_enc + expiration_enc +
                 nonce_enc + fee_bps_enc + side_enc + sig_type_enc

        struct_hash = Model.keccak256(packed)
        domain_separator = Model.domain_separator_hash(domain)
        Model.create_eip712_digest(domain_separator, struct_hash)
      end
    end
  end
end