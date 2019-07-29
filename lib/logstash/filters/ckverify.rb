# encoding: utf-8
require "logstash/filters/ck"

# The ckverify filter allows you to check if an
# event was tampered with.
#
class LogStash::Filters::CKVerify < LogStash::Filters::CK
  # The config name
  config_name "ckverify"

  public
  def multi_filter(events)
    if events.nil? || events.empty?
      return events
    end

    result = []
    events.each do |event|
      result << event
      filter(event){|new_event| result << new_event}
    end

    result
  end # def multi_filter

  public
  def multi_filter_experimental(events)
    if events.nil? || events.empty?
      return events
    end

    result = []
    hash_contents = {}
    events.each do |event|
       hash_content = hash_event(event)
       if hash_content != event.get("hash")
         event.set("verified", false)
         filter_matched(event)
         result << event
       else
         hash_contents[hash_content] = event
       end
    end

    sorted_hash_keys = hash_contents.keys.sort
    if sorted_hash_keys.empty?
      return result
    end

    sorted_asset_ids = []
    sorted_hash_keys.each do |hash|
      sorted_asset_ids << hash_contents[hash].get("entityid").to_i
    end

    uri = URI.parse(endpoint + "bulkVerify")
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = (uri.scheme == "https")
    # https.set_debug_output($stdout)

    curtoken = get_token
    params  = { 'assets': sorted_hash_keys, 'assetIds': sorted_asset_ids, 'storage': storage }
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

    sorted_results = response.body.rstrip!.split(' ')

    sorted_hash_keys.zip(sorted_results).each do |hash, verified|
      event = hash_contents[hash]
      event.set("verified", (verified == "true"))
      filter_matched(event)
      result << event
    end

    result
  end # def multi_filter_experimental

  public
  def filter(event)
    entity_id = event.get("entityid")
    hash = event.get("hash")

    hash_content = hash_event(event)

    if hash_content != hash
        event.set("verified", false)
        return filter_matched(event)
    end

    uri = URI.parse(endpoint + "verify/" + entity_id)
    uri.query = URI.encode_www_form( { :hash => hash, :storage => storage } )
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = (uri.scheme == "https")
    # https.set_debug_output($stdout)

    curtoken = get_token
    headers = { 'Content-Type' => 'application/json', 'Authorization' => "Bearer #{curtoken}" }
    request = Net::HTTP::Get.new(uri, initheader = headers)

    response = https.request(request)

    if response.code.to_i != 200
        raise 'Service Error.'
    end
    if response.body.nil?
        raise 'Response Body is nil.'
    end

    verified = response.body
    event.set("verified", (verified == "true"))

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::CKVerify
