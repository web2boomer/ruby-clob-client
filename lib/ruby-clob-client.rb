# frozen_string_literal: true

require_relative "ruby-clob-client/version"
require_relative "ruby-clob-client/client"
require_relative "ruby-clob-client/clob_types"
require_relative "ruby-clob-client/config"
require_relative "ruby-clob-client/constants"
require_relative "ruby-clob-client/endpoints"
require_relative "ruby-clob-client/exceptions"
require_relative "ruby-clob-client/headers"
require_relative "ruby-clob-client/http_helpers"
require_relative "ruby-clob-client/order_builder"
require_relative "ruby-clob-client/signer"
require_relative "ruby-clob-client/signing/eip712"
require_relative "ruby-clob-client/signing/hmac"
require_relative "ruby-clob-client/signing/model"
require_relative "ruby-clob-client/utilities"

module RubyClobClient
  class Error < StandardError; end
  # Your code goes here...
end
