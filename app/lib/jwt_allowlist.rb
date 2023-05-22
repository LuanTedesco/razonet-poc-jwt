require 'redis'

class JwtAllowlist
  KEY_PREFIX = 'token:'.freeze

  def initialize
    @redis = REDIS
  end

  def save(token, user_id, expiration = 30.days.to_i)
    @redis.hset(key(token), 'user_id', user_id)
    @redis.expire(key(token), expiration)
  end

  def revoke(token)
    @redis.del('token:' + token)
  end

  def revoke_all(user_id)
    tokens = @redis.keys("#{KEY_PREFIX}*")
    tokens.each do |token|
      hash = @redis.hgetall(token)
      @redis.del(token) if hash['user_id'] == user_id.to_s
    end
  end

  def is_valid?(token)
    @redis.exists(token) && @redis.ttl(key(token)) > 0
  end

  private

  def key(token)
    KEY_PREFIX + token
  end
end