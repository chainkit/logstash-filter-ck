# encoding: utf-8
require_relative "../spec_helper"
require "logstash/plugin"
require "logstash/event"

describe LogStash::Filters::CK do

  let(:overwrite)      { false }
  let(:target)         { "eventid" }
  let (:subject_verify){ LogStash::Filters::CKVerify.new( "username" => ENV['CKUSER'], "password" => ENV['CKPASS'] ) }
  subject              { LogStash::Filters::CK.new( "username" => ENV['CKUSER'], "password" => ENV['CKPASS'] ) }
  let(:properties)     { {:name => "foo" } }
  let(:event)          { LogStash::Event.new( properties ) }

  it "should register with logstash without errors" do
    plugin = LogStash::Plugin.lookup("filter", "ck").new( "username" => ENV['CKUSER'], "password" => ENV['CKPASS'] )
    expect { plugin.register }.to_not raise_error

    plugin = LogStash::Plugin.lookup("filter", "ckverify").new( "username" => ENV['CKUSER'], "password" => ENV['CKPASS'] )
    expect { plugin.register }.to_not raise_error
  end

  describe "should yield entityid during log generation" do
    it "should generate an entityid field" do
      subject.filter(event)
      expect(event.get('uuid')).not_to be_nil
      expect(event.get('entityid')).not_to be_nil
    end
  end

  describe "should be able to verify after log generation" do
    it "generated entityid should be verified" do
      subject.filter(event)
      subject_verify.filter(event)
      expect(event.get('verified')).to be true
    end
  end

  describe "should be able to detect log tampering" do
    it "generated entityid should be verified" do
      subject.filter(event)
      event.set('name', 'bar')
      subject_verify.filter(event)
      expect(event.get('verified')).to be false
    end
  end

end
