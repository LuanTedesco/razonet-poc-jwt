module Api
  class ApiController < ApplicationController
    before_action :authorized

    def encode_token(payload)
      payload[:jti] = SecureRandom.hex(16)
      payload[:exp] = 30.days.from_now.to_i
      JWT.encode(payload, Rails.application.credentials.jwt_secret, 'HS256')
    end

    def auth_header
      request.headers['Authorization']
    end

    def decoded_token
      return unless auth_header

      begin
        JWT.decode(@token, Rails.application.credentials.jwt_secret, true, algorithm: 'HS256')
      rescue JWT::DecodeError => error
        puts "JWT error: #{error.message}"
      rescue JWT::ExpiredSignature => error
        puts "JWT error: #{error.message}"
      end
    end

    def current_user
      set_token
      return unless decoded_token and decoded_token[0]['exp'] > Time.now.to_i

      if JwtAllowlist.new.is_valid?(@token)
        @user = User.find_by(id: decoded_token[0]['user_id'])
      end
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
      tokens = JwtTokenlist.where(user_id: decoded_token[0]['user_id'])
      for token in tokens do
        token.update(revoked: true)
      end
    end

    def is_revoked?
      return unless auth_header

      decoded_token = JWT.decode(@token, Rails.application.credentials.jwt_secret, true, algorithm: 'HS256')
      token = JwtTokenlist.where(jti: decoded_token[0]['jti'], user_id: decoded_token[0]['user_id'])
      if token.empty?
        return true
      else
        return false if token[0].revoked == false and token[0].exp > Time.now.to_i
      end
    end

    private

    def set_token
      return unless auth_header

      @token = auth_header.split(' ')[1]
    end
  end
end
