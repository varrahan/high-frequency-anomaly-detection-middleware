#include "packet_parser.h"
#include "thread_pool.h"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include <hiredis/hiredis.h>
}

#include <curl/curl.h>

using json = nlohmann::json;

static std::atomic<bool> g_shutdown{false};
static std::mutex mtx;

static void handle_signal(int) noexcept {
    g_shutdown.store(true, std::memory_order_relaxed);
}

static std::string env(const char* key, const char* fallback = "") {
    const char* v = std::getenv(key);
    return v ? v : fallback;
}

static bool post_anomaly(const AnomalyResult& res, const std::string& api_url,
                         const std::string& token) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    json body = {
        {"anomaly", {
            {"source_ip",      res.source_ip},
            {"destination_ip", res.destination_ip},
            {"protocol",       res.protocol},
            {"severity",       res.severity},
            {"score",          res.score},
            {"description",    res.description}
        }}
    };

    std::string body_str = body.dump();
    long http_code = 0;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string auth_hdr = "X-Worker-Token: " + token;
    headers = curl_slist_append(headers, auth_hdr.c_str());

    curl_easy_setopt(curl, CURLOPT_URL,            api_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,      body_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,   static_cast<long>(body_str.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,         5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](char*, size_t size, size_t nmemb, void*) -> size_t {
            return size * nmemb;
        });

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (rc == CURLE_OK && http_code == 201);
}

static void process_message(const std::string& stream_id,
    const std::string& payload,
    const std::string& api_url,
    const std::string& worker_token,
    redisContext* redis_ctx,
    const std::string& stream_name,
    const std::string& consumer_group) {
    try {
        json pkt = json::parse(payload);
        PacketFeatures features = PacketParser::extract_features(pkt);
        AnomalyResult  result   = PacketParser::score(features);

        if (result.score > 0.0) {
            bool ok = post_anomaly(result, api_url, worker_token);
            if (!ok) {
                std::cerr << "[worker] POST failed for stream_id=" << stream_id << "\n";
                return;
            }
        }

        // Lock the mutex specifically around the Redis network call
        {
            std::lock_guard<std::mutex> lock(mtx);
            redisCommand(redis_ctx, "XACK %s %s %s",
                         stream_name.c_str(),
                         consumer_group.c_str(),
                         stream_id.c_str());
        }

    } catch (const json::exception& e) {
        std::cerr << "[worker] JSON parse error for " << stream_id << ": " << e.what() << "\n";
        
        // Lock the mutex here as well before ACKing the failed parse
        {
            std::lock_guard<std::mutex> lock(mtx);
            redisCommand(redis_ctx, "XACK %s %s %s",
                         stream_name.c_str(),
                         consumer_group.c_str(),
                         stream_id.c_str());
        }
    }
}

int main() {
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT,  handle_signal);

    const std::string redis_url      = env("REDIS_URL",       "redis://localhost:6379");
    const std::string stream_name    = env("REDIS_STREAM",    "anomaly:raw");
    const std::string consumer_group = env("CONSUMER_GROUP",  "analyzers");
    const std::string consumer_name  = env("CONSUMER_NAME",   "worker-0");
    const std::string api_url        = env("RAILS_API_URL",   "http://localhost:3000/api/v1/anomalies");
    const std::string worker_token   = env("WORKER_TOKEN",    "dev-secret-change-me");
    const int         thread_count   = std::max(1, std::atoi(env("THREAD_COUNT", "0").c_str()) ?
                                           std::atoi(env("THREAD_COUNT", "0").c_str()) :
                                           static_cast<int>(std::thread::hardware_concurrency()));
    const long        batch_size     = std::atol(env("BATCH_SIZE", "64").c_str());
    const long        block_ms       = std::atol(env("BLOCK_MS",   "500").c_str());

    std::cout << "[main] Starting C++ analyzer\n"
              << "       threads=" << thread_count << "\n"
              << "       stream="  << stream_name  << "\n"
              << "       group="   << consumer_group << "\n";

    curl_global_init(CURL_GLOBAL_DEFAULT);

    struct timeval timeout = {1, 500000};
    redisContext* redis_main = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    redisContext* redis_ack = redisConnectWithTimeout("127.0.0.1", 6379, timeout);

    // Update error checking for both contexts
    if (!redis_main || redis_main->err || !redis_ack || redis_ack->err) {
        std::cerr << "[main] Redis connection error: "
                  << (redis_main && redis_main->err ? redis_main->errstr : "") 
                  << (redis_ack && redis_ack->err ? redis_ack->errstr : "") << "\n";
        return 1;
    }

    freeReplyObject(redisCommand(redis_main,
        "XGROUP CREATE %s %s $ MKSTREAM",
        stream_name.c_str(), consumer_group.c_str()));

    std::cout << "[main] Entering main loop…\n";

    // ENFORCE DESTRUCTION ORDER: ThreadPool must be inside this scope block
    {
        ThreadPool pool(static_cast<std::size_t>(thread_count));

        while (!g_shutdown.load(std::memory_order_relaxed)) {
            // Use redis_main for reading
            redisReply* claim_reply = static_cast<redisReply*>(redisCommand(redis_main,
                "XAUTOCLAIM %s %s %s 30000 0-0 COUNT %ld",
                stream_name.c_str(), consumer_group.c_str(),
                consumer_name.c_str(), batch_size));
            freeReplyObject(claim_reply);

            // Use redis_main for reading
            redisReply* read_reply = static_cast<redisReply*>(redisCommand(redis_main,
                "XREADGROUP GROUP %s %s COUNT %ld BLOCK %ld STREAMS %s >",
                consumer_group.c_str(), consumer_name.c_str(),
                batch_size, block_ms,
                stream_name.c_str()));

            if (!read_reply) continue;

            if (read_reply->type == REDIS_REPLY_ARRAY && read_reply->elements > 0) {
                redisReply* stream_entry = read_reply->element[0];
                if (stream_entry->elements >= 2) {
                    redisReply* messages = stream_entry->element[1];
                    for (std::size_t i = 0; i < messages->elements; ++i) {
                        redisReply* msg = messages->element[i];
                        if (msg->elements < 2) continue;

                        std::string stream_id = msg->element[0]->str;
                        redisReply* fields    = msg->element[1];
                        std::string payload;
                        for (std::size_t j = 0; j + 1 < fields->elements; j += 2) {
                            if (std::string(fields->element[j]->str) == "payload") {
                                payload = fields->element[j + 1]->str;
                                break;
                            }
                        }

                        if (payload.empty()) continue;
                        
                        // Pass redis_ack to the worker thread
                        pool.enqueue(process_message,
                                     stream_id, payload,
                                     api_url, worker_token,
                                     redis_ack, stream_name, consumer_group);
                    }
                }
            }
            freeReplyObject(read_reply);
        }
    } // Pool is destroyed here safely, threads join, and ACKs finish

    std::cout << "[main] Shutdown signal received, draining pool...\n";
    
    // Free both contexts
    redisFree(redis_main);
    redisFree(redis_ack);
    
    curl_global_cleanup();
    std::cout << "[main] Clean exit.\n";
    return 0;
}