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

    def self.camelize(str)
      str.to_s.gsub(/_([a-z])/) { $1.upcase }
    end

    def self.order_to_json(order, owner, order_type)
      # Convert order fields to camelCase and string values as required
      order_hash = order.to_h
      camel_order = {}
      order_hash.each do |k, v|
        camel_key = camelize(k)
        # These fields should be integers (side, signatureType)
        if %w[side signatureType].include?(camel_key)
          camel_order[camel_key] = v.to_i
        # These fields should be strings (except signature, which is a hex string)
        elsif camel_key == 'signature'
          camel_order[camel_key] = v
        else
          camel_order[camel_key] = v.to_s
        end
      end
      # Ensure tokenId is present as string (API expects tokenId, not token_id)
      if camel_order['token_id']
        camel_order['tokenId'] = camel_order.delete('token_id')
      end
      # Ensure signatureType is present as integer (API expects signatureType, not signature_type)
      if camel_order['signature_type']
        camel_order['signatureType'] = camel_order.delete('signature_type').to_i
      end
      # Ensure side is present as integer (API expects side, not side as string)
      if camel_order['side']
        camel_order['side'] = camel_order['side'].to_i
      end
      # Remove any snake_case keys left
      camel_order = camel_order.reject { |k, _| k.include?('_') }
      { order: camel_order, owner: owner, orderType: order_type }
    end

    def self.is_tick_size_smaller(a, b)
      a.to_f < b.to_f
    end

    def self.price_valid(price, tick_size)
      price >= tick_size.to_f && price <= 1 - tick_size.to_f
    end
  end
end 