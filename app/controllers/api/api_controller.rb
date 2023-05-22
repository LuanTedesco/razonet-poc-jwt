module Api
  class ApiController < ApplicationController
    before_action :set_token, only: %i[current_user authorized]
    before_action :authorized

    def encode_token(payload)
      payload[:jti] = SecureRandom.hex(16)
      payload[:exp] = 30.days.from_now.to_i
      JwtTokenlist.create(jti: payload[:jti], user_id: payload[:user_id], exp: payload[:exp])
      JWT.encode(payload, Rails.application.credentials.jwt_secret, 'HS256')
    end

    def auth_header
      request.headers['Authorization']
    end

    def decoded_token
      return unless auth_header

      begin
        JWT.decode(@token, Rails.application.credentials.jwt_secret, true, algorithm: 'HS256')
        puts "JWT decoded successfully"
      rescue JWT::DecodeError => error
        puts "JWT error: #{error.message}"
      rescue JWT::ExpiredSignature => error
        puts "JWT error: #{error.message}"
      end
    end

    def current_user
      set_token
      return unless decoded_token

      token =  decoded_token[0]

      if token.revoked == false and token.exp > Time.now.to_i
        return @user = User.find_by(id: user_id)
      else 
        return @user = nil
      end
    end

    def logged_in?
      !!current_user
    end

    def authorized
      set_token
      render json: { message: 'Please log in', revoked: is_revoked? }, status: :unauthorized unless logged_in?
    end

    def revoke_token
      token = JwtTokenlist.where(jti: decoded_token[0]['jti'], user_id: decoded_token[0]['user_id'])
      token.update(revoked: true)
    end

    def is_revoked?
      return unless auth_header

      decoded_token = JWT.decode(@token, Rails.application.credentials.jwt_secret, true, algorithm: 'HS256')
      token = JwtTokenlist.where(jti: decoded_token[0]['jti'], user_id: decoded_token[0]['user_id'])
      if token.empty?
        return false
      else
        return true if token['revoked'] == true and token.exp.to_i > Time.now.to_i
      end
    end

    private

    def set_token
      return unless auth_header
      @token = auth_header.split(' ')[1]
    end
  end
end