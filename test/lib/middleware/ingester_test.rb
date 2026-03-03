require "test_helper"
require "rack/test"
require_relative "../../../lib/middleware/ingester"

class IngesterTest < ActiveSupport::TestCase
  include Rack::Test::Methods

  def app
    Ingester.new(->(env) { [404, {}, ["Not Found"]] })
  end

  test "accepts valid requests and writes to Redis" do
    valid_token = Ingester::INGEST_TOKEN
    payload = {
      source_ip: "10.0.0.1",
      destination_ip: "10.0.0.2",
      score: "0.65",
      severity: "high"
    }.to_json

    Redis.any_instance.expects(:xadd).with(
      Ingester::STREAM_NAME,
      has_keys("ip", "rcv_at", "content_type", "payload"),
      id: "*",
      maxlen: Ingester::STREAM_MAX_LEN,
      approximate: true
    ).returns("16123456789-0")

    post Ingester::INGESTION_PATH, payload, {
      "CONTENT_TYPE" => "application/json",
      "HTTP_AUTHORIZATION" => "Bearer #{valid_token}"
    }

    assert_equal 200, last_response.status
    assert_equal "OK", last_response.body
  end

  test "rejects unauthorized requests" do
    post Ingester::INGESTION_PATH, '{"data":"test"}', {
      "CONTENT_TYPE" => "application/json",
      "HTTP_AUTHORIZATION" => "Bearer wrong-token"
    }

    assert_equal 401, last_response.status
    assert_equal "Unauthorized", last_response.body
  end

  test "rejects empty payloads" do
    post Ingester::INGESTION_PATH, "", {
      "CONTENT_TYPE" => "application/json",
      "HTTP_AUTHORIZATION" => "Bearer #{Ingester::INGEST_TOKEN}"
    }

    assert_equal 400, last_response.status
    assert_equal "Bad Request", last_response.body
  end
end