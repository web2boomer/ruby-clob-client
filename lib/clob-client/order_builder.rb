# frozen_string_literal: true
require 'bigdecimal'
require 'securerandom'
require_relative 'config'

module ClobClient
  module OrderBuilderConstants
    BUY = 'BUY'
    SELL = 'SELL'
    BUY_SIDE = 0
    SELL_SIDE = 1
  end

  module OrderBuilderHelpers
    def self.round_down(x, sig_digits)
      (x * (10**sig_digits)).floor / (10.0**sig_digits)
    end

    def self.round_normal(x, sig_digits)
      (x * (10**sig_digits)).round / (10.0**sig_digits)
    end

    def self.round_up(x, sig_digits)
      (x * (10**sig_digits)).ceil / (10.0**sig_digits)
    end

    def self.to_token_decimals(x)
      f = (10**6) * x
      f = round_normal(f, 0) if decimal_places(f) > 0
      f.to_i
    end

    def self.decimal_places(x)
      BigDecimal(x.to_s).exponent.abs
    end

    def self.generate_salt
      # Generate a unique salt for order entropy
      SecureRandom.hex(32).to_i(16)
    end
  end

  RoundConfig = Struct.new(:price, :size, :amount, keyword_init: true)

  ROUNDING_CONFIG = {
    '0.1'    => RoundConfig.new(price: 1, size: 2, amount: 3),
    '0.01'   => RoundConfig.new(price: 2, size: 2, amount: 4),
    '0.001'  => RoundConfig.new(price: 3, size: 2, amount: 5),
    '0.0001' => RoundConfig.new(price: 4, size: 2, amount: 6)
  }

  class OrderBuilder
    include OrderBuilderConstants
    include OrderBuilderHelpers

    def initialize(signer, sig_type: nil, funder: nil)
      @signer = signer
      @sig_type = sig_type || 'EOA'  # Default to EOA if not specified
      @funder = funder || @signer.address
    end

    def get_order_amounts(side, size, price, round_config)
      raw_price = OrderBuilderHelpers.round_normal(price, round_config[:price])

      if side == BUY
        raw_taker_amt = OrderBuilderHelpers.round_down(size, round_config[:size])
        raw_maker_amt = raw_taker_amt * raw_price
        if OrderBuilderHelpers.decimal_places(raw_maker_amt) > round_config[:amount]
          raw_maker_amt = OrderBuilderHelpers.round_up(raw_maker_amt, round_config[:amount] + 4)
          if OrderBuilderHelpers.decimal_places(raw_maker_amt) > round_config[:amount]
            raw_maker_amt = OrderBuilderHelpers.round_down(raw_maker_amt, round_config[:amount])
          end
        end
        maker_amount = OrderBuilderHelpers.to_token_decimals(raw_maker_amt)
        taker_amount = OrderBuilderHelpers.to_token_decimals(raw_taker_amt)
        [BUY_SIDE, maker_amount, taker_amount]  # 0 for BUY
      elsif side == SELL
        raw_maker_amt = OrderBuilderHelpers.round_down(size, round_config[:size])
        raw_taker_amt = raw_maker_amt * raw_price
        if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
          raw_taker_amt = OrderBuilderHelpers.round_up(raw_taker_amt, round_config[:amount] + 4)
          if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
            raw_taker_amt = OrderBuilderHelpers.round_down(raw_taker_amt, round_config[:amount])
          end
        end
        maker_amount = OrderBuilderHelpers.to_token_decimals(raw_maker_amt)
        taker_amount = OrderBuilderHelpers.to_token_decimals(raw_taker_amt)
        [SELL_SIDE, maker_amount, taker_amount]  # 1 for SELL
      else
        raise ArgumentError, "order_args.side must be '#{BUY}' or '#{SELL}'"
      end
    end

    def get_market_order_amounts(side, amount, price, round_config)
      raw_price = OrderBuilderHelpers.round_normal(price, round_config[:price])

      if side == BUY
        raw_maker_amt = OrderBuilderHelpers.round_down(amount, round_config[:size])
        raw_taker_amt = raw_maker_amt / raw_price
        if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
          raw_taker_amt = OrderBuilderHelpers.round_up(raw_taker_amt, round_config[:amount] + 4)
          if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
            raw_taker_amt = OrderBuilderHelpers.round_down(raw_taker_amt, round_config[:amount])
          end
        end
        maker_amount = OrderBuilderHelpers.to_token_decimals(raw_maker_amt)
        taker_amount = OrderBuilderHelpers.to_token_decimals(raw_taker_amt)
        [BUY_SIDE, maker_amount, taker_amount]  # 0 for BUY
      elsif side == SELL
        raw_maker_amt = OrderBuilderHelpers.round_down(amount, round_config[:size])
        raw_taker_amt = raw_maker_amt * raw_price
        if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
          raw_taker_amt = OrderBuilderHelpers.round_up(raw_taker_amt, round_config[:amount] + 4)
          if OrderBuilderHelpers.decimal_places(raw_taker_amt) > round_config[:amount]
            raw_taker_amt = OrderBuilderHelpers.round_down(raw_taker_amt, round_config[:amount])
          end
        end
        maker_amount = OrderBuilderHelpers.to_token_decimals(raw_maker_amt)
        taker_amount = OrderBuilderHelpers.to_token_decimals(raw_taker_amt)
        [SELL_SIDE, maker_amount, taker_amount]  # 1 for SELL
      else
        raise ArgumentError, "order_args.side must be '#{BUY}' or '#{SELL}'"
      end
    end

    def create_order(order_args, options)
      tick_size = options[:tick_size]
      neg_risk = options[:neg_risk]
      round_config = ROUNDING_CONFIG[tick_size]
      side, maker_amount, taker_amount = get_order_amounts(
        order_args.side,
        order_args.size,
        order_args.price,
        round_config
      )

      puts "[DEBUG] side: #{side}"
      puts "[DEBUG] maker_amount: #{maker_amount}"
      puts "[DEBUG] taker_amount: #{taker_amount}"
      puts "[DEBUG] round_config: #{round_config.inspect}"

      # Generate salt for order uniqueness
      salt = OrderBuilderHelpers.generate_salt
      puts "[DEBUG] salt: #{salt}"

      # Get contract config for domain (for verifyingContract)
      chain_id = @signer.get_chain_id if @signer.respond_to?(:get_chain_id)
      puts "[DEBUG] chain_id: #{chain_id}"
      contract_config = nil
      if chain_id
        contract_config = ClobClient::Config.get_contract_config(chain_id, neg_risk)
      end
      puts "[DEBUG] contract_config: #{contract_config.inspect}"

      # Create order data structure
      order_data = ClobClient::OrderData.new(
        maker: @funder,
        taker: order_args.taker,
        token_id: order_args.token_id.to_i,
        maker_amount: maker_amount.to_i,
        taker_amount: taker_amount.to_i,
        side: side,
        fee_rate_bps: order_args.fee_rate_bps.to_i,
        nonce: order_args.nonce.to_i,
        signer: @signer.address,
        expiration: order_args.expiration.to_i,
        signature_type: @sig_type || ClobClient::SignatureType::EOA,
        salt: salt
      )
      puts "[DEBUG] order_data: #{order_data.inspect}"

      # Create order fields for EIP712 signing (maintaining backward compatibility)
      order_fields = {
        maker: order_data.maker,
        taker: order_data.taker,
        token_id: order_data.token_id,
        maker_amount: order_data.maker_amount,
        taker_amount: order_data.taker_amount,
        side: order_data.side,
        fee_rate_bps: order_data.fee_rate_bps,
        nonce: order_data.nonce,
        signer: order_data.signer,
        expiration: order_data.expiration,
        signature_type: order_data.signature_type,
        salt: order_data.salt
      }
      puts "[DEBUG] order_fields: #{order_fields.inspect}"

      signature = ClobClient::Signing::EIP712.sign_order_message(@signer, order_fields)
      puts "[DEBUG] signature: #{signature.inspect}"
      order_data = order_fields.merge(signature: signature)
      order_data
    end

    def create_market_order(order_args, options)
      # stub to implement
    end

  end
end 