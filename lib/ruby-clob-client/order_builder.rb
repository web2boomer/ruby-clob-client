# frozen_string_literal: true
require 'bigdecimal'

module RubyClobClient
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

  class OrderBuilder
    include OrderBuilderConstants
    include OrderBuilderHelpers

    def initialize(signer, sig_type: nil, funder: nil)
      @signer = signer
      @sig_type = sig_type # TODO: default to EOA
      @funder = funder || @signer.address
    end

    def get_order_amounts(side, size, price, round_config)
      # TODO: Port logic from Python get_order_amounts
      nil
    end

    def get_market_order_amounts(side, amount, price, round_config)
      # TODO: Port logic from Python get_market_order_amounts
      nil
    end

    def create_order(order_args, options)
      # TODO: Port logic from Python create_order
      nil
    end

    def create_market_order(order_args, options)
      # TODO: Port logic from Python create_market_order
      nil
    end
  end
end 