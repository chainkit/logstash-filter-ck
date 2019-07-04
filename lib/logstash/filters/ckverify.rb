# encoding: utf-8
require "logstash/filters/ck"

# The ckverify filter allows you to check if an
# event was tampered with.
#
class LogStash::Filters::CKVerify < LogStash::Filters::CK
  # The config name
  config_name "ckverify"

  public
  def filter(event)
    entity_id = event.get("entityid")
    hash = event.get("hash")

    log_to_seal = Hash[event.to_hash.sort_by{ |k, v| k.to_s}]
    log_to_seal.delete("entityid")
    log_to_seal.delete("hash")
    log_to_seal = log_to_seal.to_json
    hash_content = Digest::SHA256.hexdigest(log_to_seal)

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

    verified = response.body
    event.set("verified", (verified == "true"))

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::CKVerify
