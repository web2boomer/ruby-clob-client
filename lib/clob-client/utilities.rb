# frozen_string_literal: true
require 'digest/sha1'
require 'json'

module ClobClient
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
      { order: order.to_h, owner: owner, orderType: order_type }
    end

    def self.is_tick_size_smaller(a, b)
      a.to_f < b.to_f
    end

    def self.price_valid(price, tick_size)
      price >= tick_size.to_f && price <= 1 - tick_size.to_f
    end
  end
end 