#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include "../packet_parser.h"

using json = nlohmann::json;

json get_baseline_packet() {
    return {
        {"src_ip", "10.0.0.1"},
        {"dst_ip", "10.0.0.2"},
        {"protocol", "TCP"},
        {"src_port", 54321},
        {"dst_port", 443},
        {"payload_len", 128},
        {"ttl", 64},
        {"tcp_flags", 16},
        {"payload_hex", "1a2b3c"},
        {"pkt_rate", 50.0}
    };
}

TEST(PacketParserTest, NormalTrafficHasLowScore) {
    json pkt = get_baseline_packet();
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_LT(result.score, 0.25);
    EXPECT_EQ(result.severity, "low");
}

TEST(PacketParserTest, SuspiciousPortDetection) {
    json pkt = get_baseline_packet();
    pkt["dst_port"] = 4444;
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_GE(result.score, 0.30);
    EXPECT_TRUE(result.description.find("Suspicious port") != std::string::npos);
}

TEST(PacketParserTest, SynFloodDetection) {
    json pkt = get_baseline_packet();
    pkt["tcp_flags"] = 2;       // SYN flag only
    pkt["pkt_rate"] = 15000.0;  // High packet rate
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    // +0.25 for SYN, +0.20 for high pkt_rate according to your README
    EXPECT_GE(result.score, 0.45);
    EXPECT_TRUE(result.severity == "medium" || result.severity == "high");
}

TEST(PacketParserTest, HighEntropyPayload) {
    json pkt = get_baseline_packet();
    // A highly randomized/encrypted string of hex
    pkt["payload_hex"] = "e84c9b2a7d1f3e5c8a0b9d4f6e2c1a3b5d7f9e0c2a4b6d8f1e3c5a7b9d0f2e4c";
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_GE(result.score, 0.20); 
}

TEST(PacketParserTest, ScoreDoesNotExceedMaximum) {
    json pkt = get_baseline_packet();
    pkt["dst_port"] = 1337;      // Suspicious
    pkt["tcp_flags"] = 2;        // SYN
    pkt["pkt_rate"] = 20000.0;   // Rate
    pkt["ttl"] = 255;            // Abnormal TTL
    pkt["payload_hex"] = "e84c9b2a7d1f3e5c8a0b9d4f6e2c1a3b5d7f9e0c2a4b6d8f"; // Entropy
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    // Ensure your additive scoring math clamps the maximum at 1.0
    EXPECT_LE(result.score, 1.0);
    EXPECT_EQ(result.severity, "critical");
}