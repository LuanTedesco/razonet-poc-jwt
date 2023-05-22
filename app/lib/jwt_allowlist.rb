require 'redis'

class JwtAllowlist
  def initialize
    @redis = REDIS
  end

  def save(token, user_id, expiration = 30.days.to_i)
    @redis.hset('token:' + token, 'user_id', user_id)
    @redis.expire('token:' + token, expiration)
  end

  def revoke(token)
    @redis.del('token:' + token)
  end

  def revoke_all(user_id)
    tokens = @redis.keys('token:*')
    tokens.each do |token|
      hash = @redis.hgetall(token)
      if hash['user_id'] == user_id.to_s
        @redis.del(token)
      end
    end
  end

  def is_valid?(token)
    @redis.exists(token) && @redis.ttl('token:' + token) > 0
  end
end