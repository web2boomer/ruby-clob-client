# frozen_string_literal: true

require 'eth'

module ClobClient
  class Signer
    attr_reader :private_key, :chain_id

    def initialize(private_key, chain_id)
      raise ArgumentError, 'private_key and chain_id are required' if private_key.nil? || chain_id.nil?
      @private_key = private_key
      @key = Eth::Key.new priv: private_key
      @chain_id = chain_id
    end

    def address
      @key.address.to_s
    end

    def get_chain_id
      @chain_id
    end

    def sign(message_hash)
      sig = @key.sign(message_hash)  # expects 32-byte binary
      # The signature is already a hex string, just return it
      puts "Signature object class: #{sig.class}"
      puts "Signature object: #{sig.inspect}"
      sig
    end
    
  end
end 