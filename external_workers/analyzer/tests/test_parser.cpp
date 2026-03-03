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
    EXPECT_TRUE(result.description.find("suspicious dst_port") != std::string::npos);
}

TEST(PacketParserTest, SynFloodDetection) {
    json pkt = get_baseline_packet();
    pkt["tcp_flags"] = 2;       // SYN flag only
    pkt["pkt_rate"] = 15000.0;  // High packet rate
    pkt["payload_len"] = 0;     // MUST be < 8 for SYN flood rule

    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_GE(result.score, 0.45);
    EXPECT_TRUE(result.severity == "medium" || result.severity == "high");
}

TEST(PacketParserTest, HighEntropyPayload) {
    json pkt = get_baseline_packet();
    
    // Generate a long string with all 256 byte values to guarantee high entropy
    std::string high_entropy_hex;
    for (int i = 0; i < 256; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", i);
        high_entropy_hex += buf;
    }
    // Repeat it a bit to ensure byte_count is high enough
    pkt["payload_hex"] = high_entropy_hex + high_entropy_hex;
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_GE(result.score, 0.20); 
}

TEST(PacketParserTest, ScoreDoesNotExceedMaximum) {
    json pkt = get_baseline_packet();
    pkt["dst_port"] = 1337;      // +0.30
    pkt["tcp_flags"] = 2;        
    pkt["payload_len"] = 0;      // +0.25 (SYN)
    pkt["pkt_rate"] = 20000.0;   // +0.20
    pkt["ttl"] = 255;            // +0.15
    
    PacketFeatures features = PacketParser::extract_features(pkt);
    AnomalyResult result = PacketParser::score(features);

    EXPECT_LE(result.score, 1.0);
    EXPECT_EQ(result.severity, "critical");
}