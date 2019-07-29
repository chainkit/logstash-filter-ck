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

# The ck filter allows you to generate a tamper-free
# protection for the event.
#
class LogStash::Filters::CK < LogStash::Filters::Base
  # The config name
  config_name "ck"

  # The endpoint
  config :endpoint, :validate => :string, :required => true, :default => "https://api.chainkit.com/"

  # The user, password for token
  config :username, :validate => :string, :required => false, :default => nil
  config :password, :validate => :string, :required => false, :default => nil

  # The storage
  config :storage, :validate => :string, :required => true, :default => "vmware"

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

  private
  def hash_event(event)
    if event.get("uuid").nil?
      msg_uuid = SecureRandom.uuid.force_encoding(Encoding::UTF_8)
      event.set("uuid", msg_uuid)
    end
    sorted_event = Hash[event.to_hash.sort_by{ |k, v| k.to_s}]
    sorted_event.delete("hash")
    sorted_event.delete("entityid")
    sorted_event.delete("verified")
    return Digest::SHA256.hexdigest(sorted_event.to_json)
  end # hash_event

  public
  def multi_filter(events)
    if events.nil? || events.empty?
      return events
    end

    hash_contents = {}
    events.each do |event|
      hash_content = hash_event(event)
      hash_contents[hash_content] = event
    end
    sorted_hash_keys = hash_contents.keys.sort

    uri = URI.parse(endpoint + "bulkRegister")
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = (uri.scheme == "https")
    # https.set_debug_output($stdout)

    curtoken = get_token
    params  = { 'assets': sorted_hash_keys, 'storage': storage }
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{curtoken}" }
    request = Net::HTTP::Post.new(uri.path, initheader = headers)

    request.body = params.to_json
    response = https.request(request)

    if response.code.to_i != 200
        raise 'Service Error.'
    end
    if response.body.nil?
        raise 'Response Body is nil.'
    end

    sorted_entity_ids = response.body.rstrip!.split(' ')

    result = []
    sorted_hash_keys.zip(sorted_entity_ids).each do |hash, entity_id|
      event = hash_contents[hash]
      event.set("hash", hash)
      event.set("entityid", entity_id)
      filter_matched(event)
      result << event
    end

    result
  end # def multi_filter

  public
  def filter(event)
    hash_content = hash_event(event)

    uri = URI.parse(endpoint + "register")
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = (uri.scheme == "https")
    # https.set_debug_output($stdout)

    curtoken = get_token
    params  = { 'hash': hash_content, 'description': "Sealed Log Message #{event.get('uuid')}", 'storage': storage }
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{curtoken}" }
    request = Net::HTTP::Post.new(uri.path, initheader = headers)

    request.body = params.to_json
    response = https.request(request)

    if response.code.to_i != 200
        raise 'Service Error.'
    end
    if response.body.nil?
        raise 'Response Body is nil.'
    end

    entity_id = response.body
    event.set("hash", hash_content)
    event.set("entityid", entity_id)

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::CK
