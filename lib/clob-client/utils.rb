# frozen_string_literal: true
require 'digest/sha1'
require 'json'
require 'time'

module ClobClient
  # === CONSTANTS ===
  module Constants
    L0 = 0
    L1 = 1
    L2 = 2

    CREDENTIAL_CREATION_WARNING = """🚨🚨🚨\nYour credentials CANNOT be recovered after they've been created.\nBe sure to store them safely!\n🚨🚨🚨"""

    L1_AUTH_UNAVAILABLE = 'A private key is needed to interact with this endpoint!'
    L2_AUTH_UNAVAILABLE = 'API Credentials are needed to interact with this endpoint!'
    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
    AMOY = 80002
    POLYGON = 137
    END_CURSOR = 'LTE='
  end

  # === ENDPOINTS (from Constants) ===
  module Endpoints
    TIME = "/time"
    CREATE_API_KEY = "/auth/api-key"
    GET_API_KEYS = "/auth/api-keys"
    DELETE_API_KEY = "/auth/api-key"
    DERIVE_API_KEY = "/auth/derive-api-key"
    CLOSED_ONLY = "/auth/ban-status/closed-only"
    TRADES = "/data/trades"
    GET_ORDER_BOOK = "/book"
    GET_ORDER_BOOKS = "/books"
    GET_ORDER = "/data/order/"
    ORDERS = "/data/orders"
    POST_ORDER = "/order"
    POST_ORDERS = "/orders"
    CANCEL = "/order"
    CANCEL_ORDERS = "/orders"
    CANCEL_ALL = "/cancel-all"
    CANCEL_MARKET_ORDERS = "/cancel-market-orders"
    MID_POINT = "/midpoint"
    MID_POINTS = "/midpoints"
    PRICE = "/price"
    GET_PRICES = "/prices"
    GET_SPREAD = "/spread"
    GET_SPREADS = "/spreads"
    GET_LAST_TRADE_PRICE = "/last-trade-price"
    GET_LAST_TRADES_PRICES = "/last-trades-prices"
    GET_NOTIFICATIONS = "/notifications"
    DROP_NOTIFICATIONS = "/notifications"
    GET_BALANCE_ALLOWANCE = "/balance-allowance"
    UPDATE_BALANCE_ALLOWANCE = "/balance-allowance/update"
    IS_ORDER_SCORING = "/order-scoring"
    ARE_ORDERS_SCORING = "/orders-scoring"
    GET_TICK_SIZE = "/tick-size"
    GET_NEG_RISK = "/neg-risk"
    GET_SAMPLING_SIMPLIFIED_MARKETS = "/sampling-simplified-markets"
    GET_SAMPLING_MARKETS = "/sampling-markets"
    GET_SIMPLIFIED_MARKETS = "/simplified-markets"
    GET_MARKETS = "/markets"
    GET_MARKET = "/markets/"
    GET_MARKET_TRADES_EVENTS = "/live-activity/events/"
  end

  # === UTILITIES ===
  module Utilities
    def self.parse_raw_orderbook_summary(raw_obs)
      bids = raw_obs["bids"].map { |bid| ClobClient::OrderSummary.new(size: bid["size"], price: bid["price"]) }
      asks = raw_obs["asks"].map { |ask| ClobClient::OrderSummary.new(size: ask["size"], price: ask["price"]) }
      ClobClient::OrderBookSummary.new(
        market: raw_obs["market"],
        asset_id: raw_obs["asset_id"],
        timestamp: raw_obs["timestamp"],
        bids: bids,
        asks: asks,
        hash: raw_obs["hash"]
      )
    end

    def self.generate_orderbook_summary_hash(orderbook)
      orderbook.hash = ""
      hash = Digest::SHA1.hexdigest(orderbook.to_json)
      orderbook.hash = hash
      hash
    end

    def self.order_to_json(order, owner, order_type)
      { order: order.respond_to?(:to_h) ? order.to_h : order, owner: owner, orderType: order_type }
    end

    def self.is_tick_size_smaller(a, b)
      a.to_f < b.to_f
    end

    def self.price_valid(price, tick_size)
      price >= tick_size.to_f && price <= 1 - tick_size.to_f
    end

    def self.normalize_address(address)
      # Convert address to checksum format
      # Note: This is a simplified version - you might want to use eth_utils equivalent
      address.downcase
    end

    def self.prepend_zx(in_str)
      # Prepend 0x to the input string if it is missing
      s = in_str.to_s
      if s.length > 2 && s[0..1] != "0x"
        s = "0x#{s}"
      end
      s
    end

    def self.generate_seed
      # Pseudo random seed based on timestamp
      now = Time.now.utc.to_f
      (now * rand).round
    end
  end

  # === HEADERS ===
  module Headers
    POLY_ADDRESS = 'POLY_ADDRESS'
    POLY_SIGNATURE = 'POLY_SIGNATURE'
    POLY_TIMESTAMP = 'POLY_TIMESTAMP'
    POLY_NONCE = 'POLY_NONCE'
    POLY_API_KEY = 'POLY_API_KEY'
    POLY_PASSPHRASE = 'POLY_PASSPHRASE'

    def self.create_level_1_headers(signer, nonce = nil)
      # timestamp = Time.now.to_i
      timestamp = 1751978273
      signature = ClobClient::Signing::EIP712.sign_clob_auth_message(signer, timestamp, nonce)
      # signature = '0x4e0d98e2f711669895ad08dd55bb2d00028f3235cae78e53ff6bc6c6bee2e9bc2c36659ead0968dea800f0ef3f6f16535f7dd7a4ae4c7f222c17d88ece88b3191c'
      {
        POLY_ADDRESS => signer.address,
        POLY_SIGNATURE => signature,
        POLY_TIMESTAMP => timestamp.to_s,
        POLY_NONCE => nonce.to_s
      }
    end

    def self.create_level_2_headers(signer, creds, request_args)
      timestamp = Time.now.to_i
      timestamp = 1751932804
      hmac_sig = ClobClient::Signing::HMAC.build_hmac_signature(
        creds.api_secret,
        timestamp.to_s,
        request_args.method,
        request_args.request_path,
        request_args.body
      )
      {
        POLY_ADDRESS => signer.address,
        POLY_SIGNATURE => hmac_sig,
        POLY_TIMESTAMP => timestamp.to_s,
        POLY_API_KEY => creds.api_key,
        POLY_PASSPHRASE => creds.api_passphrase
      }
    end
  end
end 