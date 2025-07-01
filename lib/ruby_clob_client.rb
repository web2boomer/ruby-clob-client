# frozen_string_literal: true

require_relative "ruby_clob_client/version"
require_relative "ruby_clob_client/client"
require_relative "ruby_clob_client/clob_types"
require_relative "ruby_clob_client/config"
require_relative "ruby_clob_client/constants"
require_relative "ruby_clob_client/endpoints"
require_relative "ruby_clob_client/exceptions"
require_relative "ruby_clob_client/headers"
require_relative "ruby_clob_client/http_helpers"
require_relative "ruby_clob_client/order_builder"
require_relative "ruby_clob_client/signer"
require_relative "ruby_clob_client/signing/eip712"
require_relative "ruby_clob_client/signing/hmac"
require_relative "ruby_clob_client/signing/model"
require_relative "ruby_clob_client/utilities"

module RubyClobClient
  class Error < StandardError; end
  # Your code goes here...
end
