require 'redis'

class JwtBlacklist
  def initialize
    @redis = REDIS
  end

  def revoke(token)
    @redis.set(token, 'revoked')
  end

  def revoked?(token)
    @redis.get(token).eql?('revoked')
  end
end