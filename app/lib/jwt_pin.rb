require 'redis'

class JwtPin
  KEY_PREFIX = 'pin:'

  def initialize
    @redis = REDIS
  end

  def save_pin(phone, pin, expiration = 3.minutes.to_i)
    @redis.set(key(phone), pin)
    @redis.expire(key(phone), expiration)
  end

  def key(phone)
    KEY_PREFIX + phone
  end
end
