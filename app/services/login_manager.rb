class LoginManager
  def self.set_timeout(user_id, user_ip)
    attempts = FailedLoginAttempts.new(user_ip:).attempts
    case attempts
    when 5
      set_login_timeout(user_ip, 30.minutes)
    when 10
      set_login_timeout(user_ip, 2.hours)
    when 15
      set_login_timeout(user_ip, 24.hours)
    else
      if attempts >= 20
        user = User.find(user_id)
        user.update_attribute(:blocked, true)
      end
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

  def self.set_login_timeout(user_ip, timeout)
    FailedLoginAttempts.new(user_ip:, timeout: timeout.to_i).set_login_timeout
  end
end
