class IpRequestLimit
  TIME_WINDOW = 2
  REQUEST_LIMIT = 1

  def initialize(app, options = {})
    @app = app
    @redis = REDIS
    @limit_routes = options[:routes]
  end

  def call(env)
    request = Rack::Request.new(env)
    ip_address = request.ip
    route = request.path_info

    if route_matches_limit_route?(route) && too_many_requests?(ip_address)
      return [
        429,
        { 'Content-Type' => 'application/json' },
        [{ error: 'Too many requests. Please try again later.' }.to_json]
      ]
    end

    @app.call(env)
  end

  private

  def route_matches_limit_route?(route)
    @limit_routes.nil? || @limit_routes.include?(route)
  end

  def too_many_requests?(ip_address)
    current_timestamp = Time.now.to_i
    key = "ip_request_limit:#{ip_address}"
    request_timestamps = @redis.zrangebyscore(key, current_timestamp - TIME_WINDOW, current_timestamp)

    return true if request_timestamps.count >= REQUEST_LIMIT

    @redis.zadd(key, current_timestamp, current_timestamp)
    @redis.expire(key, TIME_WINDOW)
    false
  end
end
