#include "packet_parser.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>

static const std::unordered_set<uint16_t> SUSPICIOUS_PORTS = {
    23,
    4444, 
    6667,
    6666,
    1337,
    31337,
    9001,
};

static const std::regex IPV4_RE(
    R"(^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$)"
);

PacketFeatures PacketParser::extract_features(const nlohmann::json& pkt) {
    PacketFeatures f{};

    f.source_ip      = pkt.value("src_ip",   "0.0.0.0");
    f.destination_ip = pkt.value("dst_ip",   "0.0.0.0");
    f.protocol       = pkt.value("protocol", "UNKNOWN");
    f.src_port       = static_cast<uint16_t>(pkt.value("src_port", 0));
    f.dst_port       = static_cast<uint16_t>(pkt.value("dst_port", 0));

    f.payload_len    = pkt.value("payload_len",    0U);
    f.ttl            = static_cast<uint8_t>(pkt.value("ttl", 64));
    f.tcp_flags      = pkt.value("tcp_flags",      0U);

    if (pkt.contains("payload_hex")) {
        f.payload_entropy = compute_entropy(pkt["payload_hex"].get<std::string>());
    }

    f.pkt_rate       = pkt.value("pkt_rate", 0.0);

    return f;
}

AnomalyResult PacketParser::score(const PacketFeatures& f) {
    double s = 0.0;
    std::vector<std::string> reasons;
    if (SUSPICIOUS_PORTS.count(f.dst_port)) {
        s += 0.30;
        reasons.push_back("suspicious dst_port=" + std::to_string(f.dst_port));
    }

    if (f.payload_entropy > 7.5) {
        s += 0.20;
        reasons.push_back("high payload entropy=" +
                           std::to_string(static_cast<int>(f.payload_entropy * 100) / 100.0));
    }

    if (f.ttl < 10 || f.ttl == 255) {
        s += 0.15;
        reasons.push_back("abnormal TTL=" + std::to_string(f.ttl));
    }

    constexpr uint8_t SYN_FLAG = 0x02;
    constexpr uint8_t ACK_FLAG = 0x10;
    if ((f.tcp_flags & SYN_FLAG) && !(f.tcp_flags & ACK_FLAG) && f.payload_len < 8) {
        s += 0.25;
        reasons.push_back("SYN-only pkt (possible SYN flood)");
    }

    if (f.pkt_rate > 10'000.0) {
        s += 0.20;
        reasons.push_back("excessive pkt_rate=" + std::to_string(static_cast<int>(f.pkt_rate)));
    }

    if (f.payload_len > 65000) {
        s += 0.10;
        reasons.push_back("oversized payload=" + std::to_string(f.payload_len));
    }

    s = std::min(s, 1.0);

    std::ostringstream desc;
    if (reasons.empty()) {
        desc << "No anomalies detected.";
    } else {
        desc << "Detected: ";
        for (std::size_t i = 0; i < reasons.size(); ++i) {
            if (i) desc << "; ";
            desc << reasons[i];
        }
        desc << ".";
    }

    return AnomalyResult{
        .source_ip      = f.source_ip,
        .destination_ip = f.destination_ip,
        .protocol       = f.protocol,
        .score          = s,
        .severity       = severity_label(s),
        .description    = desc.str()
    };
}

double PacketParser::compute_entropy(const std::string& hex) {
    if (hex.size() < 2) return 0.0;

    std::array<uint32_t, 256> freq{};
    std::size_t byte_count = 0;

    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
            ++freq[byte];
            ++byte_count;
        } catch (...) {
            continue;
        }
    }

    if (byte_count == 0) return 0.0;

    double entropy = 0.0;
    for (auto c : freq) {
        if (c == 0) continue;
        double p = static_cast<double>(c) / static_cast<double>(byte_count);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::string PacketParser::severity_label(double score) {
    if (score >= 0.75) return "critical";
    if (score >= 0.50) return "high";
    if (score >= 0.25) return "medium";
    return "low";
}