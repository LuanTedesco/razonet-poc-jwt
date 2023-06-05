class FailedLoginAttempts
  MAX_LOGIN_ATTEMPTS = 3
  ATTEMPTS_KEY_PREFIX = 'failed_login_attempts:'.freeze
  TIMEOUT_KEY_PREFIX = 'failed_login_timeout:'.freeze

  def initialize(options = {})
    @user_ip = options.fetch(:user_ip) if options.key?(:user_ip)
    @timeout = options.fetch(:timeout) if options.key?(:timeout)
    @redis = REDIS
  end

  def increment
    if @redis.exists(attempts_key)
      @redis.incr(attempts_key)
    else
      @redis.set(attempts_key, 1)
    end
  end

  def reset
    @redis.del(attempts_key)
    @redis.del(timeout_key)
  end

  def remaining_attempts
    timeouts = [5, 10, 15, 20]
    attempts = @redis.get(attempts_key).to_i

    timeouts.each do |t|
      return t - attempts if attempts <= t
    end
  end

  def attempts
    @redis.get(attempts_key).to_i
  end

  def exceeded?
    return true if @redis.ttl(attempts_key).positive?
  end

  def set_login_timeout
    @redis.set(timeout_key, 1)
    @redis.expire(timeout_key, @timeout)
  end

  def timeout
    @redis.ttl(timeout_key)
  end

  private

  def attempts_key
    "#{ATTEMPTS_KEY_PREFIX}#{@user_ip}"
  end

  def timeout_key
    "#{TIMEOUT_KEY_PREFIX}#{@user_ip}"
  end
end
