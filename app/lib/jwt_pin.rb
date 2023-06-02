require 'redis'

class JwtPin
  KEY_PREFIX = 'pin:'.freeze

  def initialize
    @redis = REDIS
  end

  def save_pin(phone, pin, expiration = 3.minutes.to_i)
    @redis.set(key(phone), pin)
    @redis.expire(key(phone), expiration)
  end

  def is_correct?(phone, pin)
    @redis.get(key(phone)).to_i == pin.to_i
  end

  def revoke_pin(phone)
    @redis.del(key(phone))
  end

  def key(phone)
    "#{KEY_PREFIX}#{phone}"
  end
end
