class LoginManager
  def self.set_timeout(user_ip)
    case FailedLoginAttempts.new(user_ip:).attempts
    when 5
      FailedLoginAttempts.new(user_ip:, timeout: 30.minutes.to_i).set_login_timeout
    when 10
      FailedLoginAttempts.new(user_ip:, timeout: 2.hours.to_i).set_login_timeout
    when 15
      FailedLoginAttempts.new(user_ip:, timeout: 24.hours.to_i).set_login_timeout
    when 20
      puts 'Account BLOCKED because due to too many attempts, contact support'
    else
      puts 'No action'
    end
  end

  def self.generate_token(user, ip_address)
    TokenManager.new(payload: {
      user_id: user.id,
      ip_address:,
      date: Time.zone.now
    }).encode_token
  end

  def self.save_token(token)
    TokenManager.new(token:).save_token
  end

  def self.increment_failed_attempts(user_ip)
    FailedLoginAttempts.new(user_ip:).increment
  end

  def self.remaining_attempts(user_ip)
    FailedLoginAttempts.new(user_ip:).remaining_attempts
  end

  def self.reset_failed_attempts(user_ip)
    FailedLoginAttempts.new(user_ip:).reset
  end
end