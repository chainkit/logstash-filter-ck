# encoding: utf-8
require "base64"
require "digest"
require "json"
require "logstash/filters/base"
require "logstash/namespace"
require "net/http"
require "securerandom"
require "time"
require "uri"

# The pd filter allows you to generate a tamper-free
# protection for the event.
#
class LogStash::Filters::PD < LogStash::Filters::Base
  config_name "pd"

  # The endpoint
  config :endpoint, :validate => :string, :required => true, :default => "https://api.pencildata.com/"

  # The user, password for token
  config :username, :validate => :string, :required => false, :default => nil
  config :password, :validate => :string, :required => false, :default => nil

  # The storage
  config :storage, :validate => :string, :required => true, :default => "public"

  # The token
  config :authtoken, :validate => :string, :required => false, :default => nil

  # Expiry
  token_expires = Time.now

  # Token
  token = nil

  private
  def get_token
    if !authtoken.nil?
        token = authtoken
    elsif token.nil? || Time.now > token_expires
      # Register and get token from endpoint
      uri = URI.parse(endpoint + "token")
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = (uri.scheme == "https")
      # https.set_debug_output($stdout)

      if username.nil? || password.nil?
          raise 'Inadequate Credentials.'
      end

      params = { 'userId': username, 'password': password }
      headers = { 'Content-Type' => 'application/json' }
      request = Net::HTTP::Post.new(uri.path, initheader = headers)

      request.body = params.to_json
      response = https.request(request)

      parsed = JSON.parse(response.body)

      token_expires = Time.now + parsed['data']['expires'].to_i
      token = parsed['data']['accessToken']
    end
    return token
  end #def get_token
  
  public
  def register
     get_token
  end # def register

  public
  def filter(event)
    msg_uuid = SecureRandom.uuid.force_encoding(Encoding::UTF_8)
    event.set("uuid", msg_uuid)

    log_to_seal = event.to_json
    hash_content = Digest::SHA256.hexdigest(log_to_seal)

    uri = URI.parse(endpoint + "register")
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true
    # https.set_debug_output($stdout)

    curtoken = get_token
    params  = { 'hash': hash_content, 'description': "Sealed Log Message #{msg_uuid}", 'storage': storage }
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer \"#{curtoken}\"" }
    request = Net::HTTP::Post.new(uri.path, initheader = headers)

    request.body = params.to_json
    response = https.request(request)

    entity_id = response.body
    event.set("entityid", entity_id)

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::PD

