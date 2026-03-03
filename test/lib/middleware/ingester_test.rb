require "rack/test"
require "test_helper"
require_relative "../../../lib/middleware/ingester"

class IngesterTest < ActiveSupport::TestCase
  include Rack::Test::Methods

  def app
    Middleware::Ingester.new(->(env) { [404, {}, ["Not Found"]] })
  end

  def setup
    ENV["INGESTION_PATH"] = "/ingest"
    ENV["INGESTION_TOKEN"] = "secret-token"
    ENV["REDIS_STREAM_NAME"] = "test:anomaly:raw"
    
    @redis_mock = Minitest::Mock.new
  end

  test "rejects unauthorized POST requests" do
    post "/ingest", '{"src_ip": "10.0.0.1"}', "CONTENT_TYPE" => "application/json"
    
    assert_equal 401, last_response.status
    assert_match /Unauthorized/, last_response.body
  end

  test "ignores requests not matching INGESTION_PATH" do
    get "/some_other_path"
    
    # Should fall through to the dummy app
    assert_equal 404, last_response.status 
  end

  test "accepts valid requests and writes to Redis" do
    header "Authorization", "Bearer secret-token"
    
    # Mocking the Redis stream append
    Redis.any_instance.expects(:xadd).with(
      ENV["REDIS_STREAM_NAME"], 
      anything, 
      maxlen: anything, 
      approximate: true
    ).returns("16123456789-0")

    post "/ingest", '{"src_ip": "10.0.0.1"}', "CONTENT_TYPE" => "application/json"
    
    assert_equal 200, last_response.status
    assert_equal '{"status":"ok"}', last_response.body
  end
end