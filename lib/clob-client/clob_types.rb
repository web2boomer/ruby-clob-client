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

  # Enum for signature types
  module SignatureType
    EOA = 0
  end

  # Order data structure matching Python OrderData
  OrderData = Struct.new(
    :maker,           # Maker of the order, i.e the source of funds for the order
    :taker,           # Address of the order taker. The zero address is used to indicate a public order
    :token_id,        # Token Id of the CTF ERC1155 asset to be bought or sold
    :maker_amount,    # Maker amount, i.e the max amount of tokens to be sold
    :taker_amount,    # Taker amount, i.e the minimum amount of tokens to be received
    :side,            # The side of the order, BUY or SELL
    :fee_rate_bps,    # Fee rate, in basis points, charged to the order maker, charged on proceeds
    :nonce,           # Nonce used for onchain cancellations
    :signer,          # Signer of the order. Optional, if it is not present the signer is the maker of the order
    :expiration,      # Timestamp after which the order is expired
    :signature_type,  # Signature type used by the Order. Default value 'EOA'
    :salt,            # Unique salt to ensure entropy
    keyword_init: true
  ) do
    def initialize(*args)
      super
      # Set default values
      self.taker ||= ClobClient::Constants::ZERO_ADDRESS
      self.nonce ||= "0"
      self.expiration ||= "0"
      self.signature_type ||= SignatureType::EOA
    end
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