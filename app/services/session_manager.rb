class SessionManager < ApplicationController
  def initialize(options = {})
    @token = options.fetch(:token) if options.key?(:token)
    @decoded_token = TokenManager.new(token: @token).decoded_token
    @user_id = @decoded_token.first['user_id'] if @decoded_token
  end

  def active_sessions
    sessions = JwtAllowlist.new.active_sessions(@user_id, @token).map do |token|
      decoded_token = TokenManager.new(token: token[:token]).decoded_token
      return unless decoded_token

      {
        token: token[:token],
        ip_address: decoded_token.first['ip_address'],
        date: decoded_token.first['date']
      }
    end
  end

  def current_user
    return unless @decoded_token && @decoded_token.first['exp'] > Time.now.to_i

    user ||= User.find_by(id: @user_id) if JwtAllowlist.new.is_valid?(@user_id, @token)
  end

  def logged_in?
    !!SessionManager.new(token: @token).current_user
  end
end
