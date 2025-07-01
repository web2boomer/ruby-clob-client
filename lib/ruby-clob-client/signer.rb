# frozen_string_literal: true

require 'eth'

module RubyClobClient
  class Signer
    attr_reader :private_key, :chain_id

    def initialize(private_key, chain_id)
      raise ArgumentError, 'private_key and chain_id are required' if private_key.nil? || chain_id.nil?
      @private_key = private_key
      @key = Eth::Key.new priv: private_key
      @chain_id = chain_id
    end

    def address
      @key.address
    end

    def get_chain_id
      @chain_id
    end

    def sign(message_hash)
      # message_hash should be a hex string ("0x...") or binary string
      hash = message_hash.start_with?("0x") ? [message_hash[2..]].pack('H*') : message_hash
      sig = Eth::Key.personal_sign(hash, @key)
      sig.unpack1('H*').prepend('0x')
    end
  end
end 