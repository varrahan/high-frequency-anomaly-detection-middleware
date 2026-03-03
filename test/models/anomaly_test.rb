require "test_helper"

class AnomalyTest < ActiveSupport::TestCase
  test "is valid with proper attributes" do
    anomaly = Anomaly.new(
      source_ip: "10.0.0.1", 
      destination_ip: "10.0.0.2", 
      protocol: "TCP",
      score: 0.65, 
      severity: "high",
      description: "Suspicious port 4444",
      raw_payload: "deadbeef",
      detected_at: Time.current
    )
    assert anomaly.valid?
  end

  test "broadcasts to Turbo Stream after creation" do
    anomaly = Anomaly.new(
      source_ip: "10.0.0.1", 
      destination_ip: "10.0.0.2", 
      protocol: "TCP",
      score: 0.9, 
      severity: "critical"
    )
    
    assert_broadcast_on("anomalies", capture: true) do
      anomaly.save!
    end
  end
end