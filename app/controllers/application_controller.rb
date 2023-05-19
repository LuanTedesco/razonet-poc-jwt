class ApplicationController < ActionController::API
  before_action :authorized

  def encode_token(payload)
    payload[:jti] = SecureRandom.hex(16)
    JWT.encode(payload, Rails.application.credentials.jwt_secret, 'HS256')
  end

  def auth_header
    request.headers['Authorization']
  end

  def decoded_token
    return unless auth_header

    token = auth_header.split(' ')[1]

    begin
      JWT.decode(token, Rails.application.credentials.jwt_secret, true, algorithm: 'HS256')
    rescue JWT::DecodeError => error
      puts "JWT error: #{error.message}"
    rescue JWT::ExpiredSignature => error
      puts "JWT error: #{error.message}"
    end
  end

  def current_user
    return unless decoded_token && !is_revoked?

    user_id = decoded_token[0]['user_id']
    @user = User.find_by(id: user_id)
  end

  def logged_in?
    !!current_user
  end

  def authorized
    render json: { message: 'Please log in', revoked: is_revoked? }, status: :unauthorized unless logged_in?
  end

  def revoke_token(token)
    begin
      JwtBlacklist.new.revoke(token)
    rescue Redis::CannotConnectError => error
      puts "Redis error: #{error.message}"
    end
  end

  def is_revoked?
    return unless auth_header

    token = auth_header.split(' ')[1]
    JwtBlacklist.new.revoked?(token)
  end
end
