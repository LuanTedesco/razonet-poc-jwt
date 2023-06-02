require 'redis'

class JwtAllowlist
  KEY_PREFIX = 'token:'.freeze

  def initialize(options = {})
    @redis = REDIS
  end

  def save(user_id, token, expiration = 30.days.to_i)
    @redis.set(key(user_id, token), token)
    @redis.expire(key(user_id, token), expiration)
  end

  def revoke(user_id, token)
    @redis.del(key(user_id, token))
  end

  def revoke_all(user_id, current_token)
    tokens = @redis.keys("#{KEY_PREFIX + user_id.to_s}:*")

    tokens.each do |token|
      @redis.del(token) if token.split(':').last != current_token
    end
  end

  def revoke_all_by_id(user_id, token)
    tokens = @redis.keys("#{KEY_PREFIX + user_id.to_s}:*")

    tokens.each do |token|
      @redis.del(token)
    end
  end

  def is_valid?(user_id, token)
    @redis.exists(key(user_id, token))
  end

  def active_sessions(user_id, current_token)
    sessions = []
    tokens = @redis.keys("#{KEY_PREFIX + user_id.to_s}:*")

    tokens.each do |token|
      next unless token.split(':').last != current_token

      session = {
        token: token.split(':').last
      }
      sessions << session
    end

    sessions
  end

  private

  def key(user_id, token)
    "#{KEY_PREFIX}#{user_id}:#{token}"
  end
end
