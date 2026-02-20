class AnomalyIngester
  INGESTION_PATH    = ENV.fetch("INGESTION_PATH",    "/ingest")
  STREAM_NAME       = ENV.fetch("REDIS_STREAM_NAME", "anomaly:raw")
  INGEST_TOKEN      = ENV.fetch("INGESTION_TOKEN",   "dev-ingest-token")
  STREAM_MAX_LEN    = ENV.fetch("STREAM_MAX_LEN",    "50000").to_i
  OK_RESPONSE       = [200, { "Content-Type" => "text/plain", "Content-Length" => "2" }, ["OK"]].freeze
  UNAUTHORIZED      = [401, { "Content-Type" => "text/plain", "Content-Length" => "12" }, ["Unauthorized"]].freeze
  BAD_REQUEST       = [400, { "Content-Type" => "text/plain", "Content-Length" => "11" }, ["Bad Request"]].freeze

  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    unless request.post? && request.path == INGESTION_PATH
      return @app.call(env)
    end

    auth_header = env["HTTP_AUTHORIZATION"].to_s
    bearer      = auth_header.sub(/\ABearer\s+/i, "")

    unless ActiveSupport::SecurityUtils.secure_compare(bearer, INGEST_TOKEN)
      log_warn("Rejected unauthenticated ingestion attempt from #{request.ip}")
      return UNAUTHORIZED
    end

    body = request.body.read.freeze
    request.body.rewind

    if body.empty?
      log_warn("Received empty payload from #{request.ip}")
      return BAD_REQUEST
    end

    metadata = {
      "ip"         => request.ip.to_s,
      "rcv_at"     => Time.now.utc.to_f.to_s,
      "content_type" => (request.content_type || "application/octet-stream"),
      "payload"    => body
    }

    $redis_pool.with do |conn|
      conn.xadd(STREAM_NAME, metadata, id: "*", maxlen: STREAM_MAX_LEN, approximate: true)
    end

    OK_RESPONSE

  rescue Redis::BaseError => e
    log_error("Redis write failed: #{e.message}")
    [503, { "Content-Type" => "text/plain" }, ["Service Unavailable"]]
  end

  private

  def log_warn(msg)  = Rails.logger&.warn("[AnomalyIngester] #{msg}")
  def log_error(msg) = Rails.logger&.error("[AnomalyIngester] #{msg}")
end