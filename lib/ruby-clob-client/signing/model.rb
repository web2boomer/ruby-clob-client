# frozen_string_literal: true

require 'eth'
require 'digest/keccak'

module RubyClobClient
  module Signing
    module Model
      def self.keccak256(data)
        Digest::Keccak.digest(data, 256)
      end

      def self.encode_uint256(val)
        [val.to_i.to_s(16).rjust(64, '0')].pack('H*')  # 32-byte hex
      end

      def self.encode_address(addr)
        clean = addr.downcase.gsub(/^0x/, '').rjust(64, '0')
        [clean].pack('H*')  # 32 bytes
      end

      def self.encode_string(str)
        keccak256(str) # ensure string
      end

      def self.domain_separator_hash(domain)
        type_hash     = keccak256("EIP712Domain(string name,string version,uint256 chainId)")
        name_hash     = encode_string(domain[:name])
        version_hash  = encode_string(domain[:version])
        chain_id_enc  = encode_uint256(domain[:chainId])
        packed = type_hash + name_hash + version_hash + chain_id_enc
        keccak256(packed)
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
        message_hash   = Model.encode_string(@message)

        packed = TYPE_HASH + address_enc + timestamp_enc + nonce_enc + message_hash
        struct_hash = Model.keccak256(packed)

        domain_separator = Model.domain_separator_hash(domain)
        to_sign = "\x19\x01" + domain_separator + struct_hash
        puts "==== SIGNATURE DEBUG ===="
        puts "address:         #{@address}"
        puts "timestamp:       #{@timestamp}"
        puts "timestamp:       #{@timestamp} (#{Time.at(@timestamp.to_i).to_fs})"
        puts "nonce:           #{@nonce}"
        puts "message:         #{@message}"
        puts "address_enc:     0x#{Model.encode_address(@address).unpack1('H*')}"
        puts "timestamp_enc:   0x#{Model.encode_string(@timestamp.to_s).unpack1('H*')}"
        puts "nonce_enc:       0x#{Model.encode_uint256(@nonce).unpack1('H*')}"
        puts "message_hash:    0x#{Model.encode_string(@message).unpack1('H*')}"
        puts "TYPE_HASH:       0x#{TYPE_HASH.unpack1('H*')}"
        puts "struct_hash:     0x#{struct_hash.unpack1('H*')}"
        puts "domain_separator:0x#{domain_separator.unpack1('H*')}"
        puts "final_digest:    0x#{Model.keccak256(to_sign).unpack1('H*')}"          
        Model.keccak256(to_sign)
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
        token_id_enc    = Model.encode_address(@token_id)
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
        to_sign = "\x19\x01" + domain_separator + struct_hash
        Model.keccak256(to_sign)
      end
    end
  end
end