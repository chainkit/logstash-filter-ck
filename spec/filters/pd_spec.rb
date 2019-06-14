# encoding: utf-8
require_relative "../spec_helper"
require "logstash/plugin"
require "logstash/event"

describe LogStash::Filters::PD do

  let(:overwrite)   { false }
  let(:target)     { "eventid" }
  subject          { LogStash::Filters::PD.new( "username" => ENV['PDUSER'], "password" => ENV['PDPASS'] ) }

  let(:properties) { {:name => "foo" } }
  let(:event)      { LogStash::Event.new(properties) }

  it "should register with logstash without errors" do
    plugin = LogStash::Plugin.lookup("filter", "pd").new( "username" => ENV['PDUSER'], "password" => ENV['PDPASS'] )
    expect { plugin.register }.to_not raise_error
  end

  describe "should yield entity_id during log generation" do
    it "should generate an entityid field" do
      subject.filter(event)
      expect(event.get('uuid')).not_to be_nil
      expect(event.get('entityid')).not_to be_nil
    end
  end

end
