module Api
  class ApiController < ApplicationController
    before_action :authorized

    def encode_token(payload)
      payload[:jti] = SecureRandom.hex(16)
      payload[:exp] = 30.days.from_now.to_i
      JWT.encode(payload, jwt_secret, 'HS256')
    end

    def decoded_token
      return unless auth_header

      begin
        JWT.decode(@token, jwt_secret, true, algorithm: 'HS256')
      rescue JWT::DecodeError, JWT::ExpiredSignature => error
        puts "JWT error: #{error.message}"
      end
    end

    def current_user
      set_token
      return unless decoded_token and decoded_token.first['exp'] > Time.now.to_i

      @user ||= User.find_by(id: decoded_token.first['user_id']) if JwtAllowlist.new.is_valid?(@token)
    end

    def logged_in?
      !!current_user
    end

    def authorized
      render json: { message: 'Please login' }, status: :unauthorized unless logged_in?
    end

    def save_token(token, user_id)
      JwtAllowlist.new.save(token, user_id)
    end

    def revoke_token
      JwtAllowlist.new.revoke(@token)
    end

    def revoke_all_tokens
      user_id = decoded_token.first['user_id']
      JwtAllowlist.new.revoke_all(user_id)
    end

    private

    def set_token
      return unless auth_header

      @token ||= auth_header.split(' ').last
    end

    def jwt_secret
      Rails.application.credentials.jwt_secret
    end

    def auth_header
      request.headers['Authorization']
    end
  end
end
