# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "securerandom"

# The pd filter allows you to generate a tamper-free
# protection for the event.
#
class LogStash::Filters::PD < LogStash::Filters::Base
  config_name "pd"

  # Select the name of the field where the generated UUID should be
  # stored.
  #
  # Example:
  # [source,ruby]
  #     filter {
  #       uuid {
  #         target => "uuid"
  #       }
  #     }
  config :target, :validate => :string, :required => true

  # If the value in the field currently (if any) should be overridden
  # by the generated UUID. Defaults to `false` (i.e. if the field is
  # present, with ANY value, it won't be overridden)
  #
  # Example:
  # [source,ruby]
  #    filter {
  #       uuid {
  #         target    => "uuid"
  #         overwrite => true
  #       }
  #    }
  config :overwrite, :validate => :boolean, :default => false

  public
  def register
  end # def register

  public
  def filter(event)
    
    # SecureRandom.uuid returns a non UTF8 string and since
    # only UTF8 strings can be passed to a LogStash::Event
    # we need to reencode it here
    if overwrite
      event.set(target, SecureRandom.uuid.force_encoding(Encoding::UTF_8))
    elsif event.get(target).nil?
      event.set(target, SecureRandom.uuid.force_encoding(Encoding::UTF_8))
    end

    filter_matched(event)
  end # def filter

end # class LogStash::Filters::PD

