# ruby-clob-client - Work in progress!!!

Ruby client for the Polymarket CLOB. Full API documentation can be found [here](https://docs.polymarket.com/developers/dev-resources/main). Ported from [py-clob-client](https://github.com/Polymarket/py-clob-client).

### Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add 'ruby-clob-client'

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install 'ruby-clob-client'

### Requisites

#### Allowances
Adjusting and setting allowances is only required when using an EOA or a web3 wallet like MetaMask. If you sign in with a Magic link or email login, allowances are automatically configured for you during account creation.

If you are interacting with the API with an EOA or web3/MetaMask wallet then correct token allowances must be set before orders can be placed. 
The following mainnet (Polygon) allowances should be set by the funding (maker) address. For additional documentation please refer to the [API documentation](https://polymarket.github.io/slate-docs/#introduction).

|                   token(s)                   |                   spender                    |                                  description                                   |
| :------------------------------------------: | :------------------------------------------: | :----------------------------------------------------------------------------: |
| `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174` | `0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E` |            allow the CTF Exchange contract to transfer user's usdc             |
| `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174` | `0xC5d563A36AE78145C45a50134d48A1215220f80a` |        allow the Neg Risk CTF Exchange contract to transfer user's usdc        |
| `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174` | `0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296` |          allow the Neg Risk Adapter contract to transfer user's usdc           |
| `0x4D97DCd97eC945f40cF65F87097ACe5EA0476045` | `0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E` |     allow the CTF Exchange contract to transfer user's conditional tokens      |
| `0x4D97DCd97eC945f40cF65F87097ACe5EA0476045` | `0xC5d563A36AE78145C45a50134d48A1215220f80a` | allow the Neg Risk CTF Exchange contract to transfer user's conditional tokens |
| `0x4D97DCd97eC945f40cF65F87097ACe5EA0476045` | `0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296` |   allow the Neg Risk Adapter contract to transfer user's conditional tokens    |

See [this gist](https://gist.github.com/poly-rodr/44313920481de58d5a3f6d1f8226bd5e) for a an example of how to set these allowances for an account using python.

### Usage

Below is a comprehensive usage guide for the ruby-clob-client gem. This client supports both Level 1 (private key) and Level 2 (API credentials) authentication modes.

#### Basic Setup

First, require the gem and initialize a client:

```ruby
require 'ruby-clob-client'

# Initialize with host URL (use appropriate environment)
client = RubyClobClient::Client.new(
  host: 'https://clob.polymarket.com',  # Production
  # host: 'https://clob-staging.polymarket.com',  # Staging
  chain_id: RubyClobClient::Constants::POLYGON  # 137 for Polygon mainnet
)
```

#### Authentication

The client supports two authentication levels:

**Level 1 Authentication (Private Key)**
```ruby
# Initialize with private key for Level 1 auth
client = RubyClobClient::Client.new(
  host: 'https://clob.polymarket.com',
  chain_id: RubyClobClient::Constants::POLYGON,
  key: 'your_private_key_here'  # 0x-prefixed private key
)

# Get your wallet address
address = client.get_address
puts "Wallet address: #{address}"
```

**Level 2 Authentication (API Credentials)**
```ruby
# Create API credentials (requires Level 1 auth first)
creds = client.create_api_key
puts RubyClobClient::Constants::CREDENTIAL_CREATION_WARNING
puts "API Key: #{creds.api_key}"
puts "Secret: #{creds.api_secret}"
puts "Passphrase: #{creds.api_passphrase}"

# Set credentials for Level 2 auth
client.set_api_creds(creds)
```

#### Market Data

Get market information and pricing data:

```ruby
# Get all markets
markets = client.get_markets
puts "Available markets: #{markets}"

# Get order book for a specific token
token_id = "0x1234567890abcdef..."  # Replace with actual token ID
order_book = client.get_order_book(token_id)
puts "Order book: #{order_book}"

# Get current price for a token
price_response = client.get_price(token_id, "BUY")
puts "Current buy price: #{price_response.body}"

# Get spread information
spread_response = client.get_spread(token_id)
puts "Spread: #{spread_response.body}"
```

#### Placing Orders

**Limit Orders**
```ruby
# Create order arguments
order_args = RubyClobClient::OrderArgs.new(
  token_id: "0x1234567890abcdef...",  # Token ID
  price: 0.65,                        # Price in USD
  size: 100,                          # Size in token units
  side: "BUY",                        # "BUY" or "SELL"
  fee_rate_bps: 0,                    # Fee rate in basis points
  nonce: Time.now.to_i,               # Nonce for order uniqueness
  expiration: Time.now.to_i + 3600    # Expiration timestamp
)

# Create and post the order
order = client.create_and_post_order(order_args)
puts "Order created: #{order}"
```

**Market Orders**
```ruby
# Create market order arguments
market_order_args = RubyClobClient::MarketOrderArgs.new(
  token_id: "0x1234567890abcdef...",
  amount: 100,                        # Amount in USD
  side: "BUY",
  order_type: RubyClobClient::OrderType::FOK  # Fill or Kill
)

# Create and post market order
market_order = client.create_and_post_order(market_order_args)
puts "Market order created: #{market_order}"
```

#### Order Management

```ruby
# Get your open orders
orders = client.get_orders
puts "Open orders: #{orders}"

# Get specific order details
order_id = "your_order_id"
order_details = client.get_order(order_id)
puts "Order details: #{order_details}"

# Cancel a specific order
cancel_response = client.cancel(order_id)
puts "Cancel response: #{cancel_response}"

# Cancel all orders
cancel_all_response = client.cancel_all
puts "Cancel all response: #{cancel_all_response}"
```

#### Trading History

```ruby
# Get your trade history
trades = client.get_trades
puts "Trade history: #{trades}"

# Get last trade price for a token
last_trade = client.get_last_trade_price(token_id)
puts "Last trade price: #{last_trade.body}"
```

#### Balance and Allowances

```ruby
# Check balance and allowance (requires Level 2 auth)
# Note: This feature is currently under development
balance = client.get_balance_allowance
puts "Balance and allowance: #{balance}"

# Update allowance (requires Level 2 auth)
# Note: This feature is currently under development
update_response = client.update_balance_allowance
puts "Allowance update: #{update_response}"
```

#### Complete Example

Here's a complete example showing how to place a limit order:

```ruby
require 'ruby-clob-client'

# Initialize client with private key
client = RubyClobClient::Client.new(
  host: 'https://clob.polymarket.com',
  chain_id: RubyClobClient::Constants::POLYGON,
  key: 'your_private_key_here'
)

# Get market data
token_id = "0x1234567890abcdef..."  # Replace with actual token ID
order_book = client.get_order_book(token_id)
puts "Order book retrieved"

# Place a limit order
order_args = RubyClobClient::OrderArgs.new(
  token_id: token_id,
  price: 0.65,
  size: 100,
  side: "BUY",
  fee_rate_bps: 0,
  nonce: Time.now.to_i,
  expiration: Time.now.to_i + 3600
)

order = client.create_and_post_order(order_args)
puts "Order placed successfully: #{order}"

# Monitor the order
sleep(5)
orders = client.get_orders
puts "Current orders: #{orders}"
```

#### Error Handling

The client includes comprehensive error handling:

```ruby
begin
  order = client.create_and_post_order(order_args)
  puts "Order successful: #{order}"
rescue RubyClobClient::Error => e
  puts "CLOB error: #{e.message}"
rescue StandardError => e
  puts "Unexpected error: #{e.message}"
end
```

#### Important Notes

1. **Token Allowances**: Ensure proper token allowances are set before trading (see Requisites section above)
2. **Network Selection**: Use appropriate `chain_id` for your target network (Polygon mainnet or Amoy testnet)
3. **Rate Limiting**: Be mindful of API rate limits when making multiple requests
4. **Order Expiration**: Always set appropriate expiration times for your orders
5. **Security**: Keep your private keys and API credentials secure
6. **Development Status**: This gem is currently in development. Some features may be incomplete or subject to change

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).
