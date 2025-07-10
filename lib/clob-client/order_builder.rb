# frozen_string_literal: true
require 'bigdecimal'
require_relative 'config'

module ClobClient
  module OrderBuilderConstants
    BUY = 'BUY'
    SELL = 'SELL'
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
        [BUY, maker_amount, taker_amount]
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
        [SELL, maker_amount, taker_amount]
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
        [BUY, maker_amount, taker_amount]
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
        [SELL, maker_amount, taker_amount]
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

      # Get contract config for domain (for verifyingContract)
      chain_id = @signer.get_chain_id if @signer.respond_to?(:get_chain_id)
      contract_config = nil
      if chain_id
        contract_config = ClobClient::Config.get_contract_config(chain_id, neg_risk)
      end

      # Create order fields for EIP712 signing
      order_fields = {
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
        signature_type: @sig_type || 'EOA'
      }

      # Build EIP712 domain with verifyingContract if available
      domain = if contract_config
        {
          name: ClobClient::Signing::EIP712::CLOB_DOMAIN_NAME,
          version: ClobClient::Signing::EIP712::CLOB_VERSION,
          chainId: chain_id,
          verifyingContract: contract_config.exchange
        }
      else
        ClobClient::Signing::EIP712.get_clob_auth_domain(chain_id)
      end

      p "domain"
      ap domain

      signature = ClobClient::Signing::EIP712.sign_order_message(@signer, order_fields, domain)

      p "signature"
      ap signature

      # This is the same as order_fields, but with the signature added.
      order_data = order_fields.merge(signature: signature)

      ap order_data

      order_data
    end

    def create_market_order(order_args, options)
      tick_size = options[:tick_size]
      round_config = ROUNDING_CONFIG[tick_size]
      side, maker_amount, taker_amount = get_market_order_amounts(
        order_args.side,
        order_args.amount,
        order_args.price,
        round_config
      )

      # Create order fields for EIP712 signing
      order_fields = {
        maker: @funder,
        taker: order_args.taker,
        token_id: order_args.token_id,
        maker_amount: maker_amount,
        taker_amount: taker_amount,
        side: side,
        fee_rate_bps: order_args.fee_rate_bps.to_s,
        nonce: order_args.nonce.to_s,
        signer: @signer.address,
        expiration: '0',
        signature_type: @sig_type || 'EOA'
      }
      signature = ClobClient::Signing::EIP712.sign_order_message(@signer, order_fields)

      # This is the same as order_fields, but with the signature added.
      order_data = order_fields.merge(signature: signature)

      order_data
    end
  end
end 