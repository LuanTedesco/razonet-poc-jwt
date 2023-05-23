class SessionManager < ApplicationController
  def initialize(options = {})
    @token = options.fetch(:token) if options.key?(:token)
  end

  def active_sessions
    user_id = TokenManager.new(token: @token).decoded_token.first['user_id']
    JwtAllowlist.new.active_sessions(user_id)
  end

  def current_user
    decoded_token = TokenManager.new(token: @token).decoded_token
    return unless decoded_token && decoded_token.first['exp'] > Time.now.to_i

    @user ||= User.find_by(id: decoded_token.first['user_id']) if JwtAllowlist.new.is_valid?(@token)
  end

  def logged_in?
    !!SessionManager.new(token: @token).current_user
  end
end
