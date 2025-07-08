# frozen_string_literal: true

module ClobClient
  module ClobTypes
    # TODO: Port types from Python clob_types.py
  end

  # Enum for order types
  module OrderType
    GTC = :GTC
    FOK = :FOK
    GTD = :GTD
    FAK = :FAK
  end

  # API Credentials
  ApiCreds = Struct.new(:api_key, :api_secret, :api_passphrase, keyword_init: true)

  # Request arguments
  RequestArgs = Struct.new(:method, :request_path, :body, keyword_init: true)

  # Book parameters
  BookParams = Struct.new(:token_id, :side, keyword_init: true)

  # Order arguments
  OrderArgs = Struct.new(
    :token_id, :price, :size, :side, :fee_rate_bps, :nonce, :expiration, :taker,
    keyword_init: true
  )

  # Market order arguments
  MarketOrderArgs = Struct.new(
    :token_id, :amount, :side, :price, :fee_rate_bps, :nonce, :taker, :order_type,
    keyword_init: true
  )

  # Trade parameters
  TradeParams = Struct.new(:id, :maker_address, :market, :asset_id, :before, :after, keyword_init: true)

  # Open order parameters
  OpenOrderParams = Struct.new(:id, :market, :asset_id, keyword_init: true)

  # Drop notification parameters
  DropNotificationParams = Struct.new(:ids, keyword_init: true)

  # Order summary
  class OrderSummary
    attr_accessor :price, :size
    def initialize(price: nil, size: nil)
      @price = price
      @size = size
    end
    def to_h
      { price: @price, size: @size }
    end
    def to_json(*_args)
      to_h.to_json
    end
  end

  # Order book summary
  class OrderBookSummary
    attr_accessor :market, :asset_id, :timestamp, :bids, :asks, :hash
    def initialize(market: nil, asset_id: nil, timestamp: nil, bids: nil, asks: nil, hash: nil)
      @market = market
      @asset_id = asset_id
      @timestamp = timestamp
      @bids = bids
      @asks = asks
      @hash = hash
    end
    def to_h
      { market: @market, asset_id: @asset_id, timestamp: @timestamp, bids: @bids, asks: @asks, hash: @hash }
    end
    def to_json(*_args)
      to_h.to_json
    end
  end
end 