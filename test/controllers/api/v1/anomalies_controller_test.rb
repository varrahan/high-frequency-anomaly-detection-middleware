require "test_helper"

class Api::V1::AnomaliesControllerTest < ActionDispatch::IntegrationTest
  setup do
    ENV["ANOMALY_WORKER_TOKEN"] = "worker-secret"
    @valid_headers = {
      "X-Worker-Token" => "worker-secret",
      "Content-Type" => "application/json"
    }
  end

  test "creates anomaly and broadcasts to dashboard with valid token" do
    payload = {
      source_ip: "192.168.1.10", 
      destination_ip: "10.0.0.2", 
      protocol: "TCP",
      score: 0.65, 
      severity: "high",
      description: "Suspicious port 4444",
      raw_payload: "ljksfajkfbfbajkfna",
      detected_at: Time.current
    }

    assert_difference("Anomaly.count", 1) do
      post api_v1_anomalies_url, params: { anomaly: payload }, headers: @valid_headers, as: :json
    end

    assert_response :created
    assert_equal "192.168.1.10", Anomaly.last.source_ip
  end

  test "rejects webhook from worker without token" do
    payload = {
      source_ip: "10.0.0.1", 
      destination_ip: "10.0.0.2", 
      protocol: "TCP",
      score: 0.65, 
      severity: "high",
      description: "Suspicious port 4444",
      raw_payload: "ljksfajkfbfbajkfna",
      detected_at: Time.current
    }
    post api_v1_anomalies_url, params: { anomaly: payload }, as: :json
    assert_response :unauthorized
  end
end