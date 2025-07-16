# frozen_string_literal: true

require_relative "clob-client/version"
require_relative "clob-client/client"
require_relative "clob-client/clob_types"
require_relative "clob-client/config"
require_relative "clob-client/constants"
require_relative "clob-client/endpoints"
require_relative "clob-client/exceptions"
require_relative "clob-client/headers"
require_relative "clob-client/http_helpers"
require_relative "clob-client/order_builder"
require_relative "clob-client/signer"
require_relative "clob-client/signing"
require_relative "clob-client/utilities"

module ClobClient
  class Error < StandardError; end
  # Your code goes here...
end
