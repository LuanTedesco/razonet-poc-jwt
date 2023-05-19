require 'redis'

class JwtBlacklist
  def initialize
    @redis = REDIS
  end

  def revoke(token, expiration)
    @redis.setex(token, expiration, 'revoked')
  end

  def revoked?(token)
    @redis.get(token) == 'revoked'
  end
end