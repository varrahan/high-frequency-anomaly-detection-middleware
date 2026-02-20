#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

struct PacketFeatures {
    std::string  source_ip;
    std::string  destination_ip;
    std::string  protocol;
    uint16_t     src_port       = 0;
    uint16_t     dst_port       = 0;
    uint32_t     payload_len    = 0;
    uint8_t      ttl            = 64;
    uint8_t      tcp_flags      = 0;
    double       payload_entropy= 0.0;
    double       pkt_rate       = 0.0;
};

struct AnomalyResult {
    std::string  source_ip;
    std::string  destination_ip;
    std::string  protocol;
    double       score       = 0.0; 
    std::string  severity;         
    std::string  description;
};

class PacketParser {
public:
    static PacketFeatures extract_features(const nlohmann::json& pkt);
    static AnomalyResult  score(const PacketFeatures& features);

private:
    static double      compute_entropy(const std::string& hex);
    static std::string severity_label(double score);
};