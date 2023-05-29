class TokenManager < ApplicationController
  def initialize(options = {})
    @token = options.fetch(:token) if options.key?(:token)
    @payload = options.fetch(:payload) if options.key?(:payload)
    @user_id = decoded_token.first['user_id'] if options.key?(:token) && decoded_token
  end

  def encode_token
    @payload[:jti] = SecureRandom.hex(16)
    @payload[:exp] = 30.days.from_now.to_i
    JWT.encode(@payload, jwt_secret, 'HS256')
  end

  def decoded_token
    JWT.decode(@token, jwt_secret, true, algorithm: 'HS256')
  rescue JWT::DecodeError, JWT::ExpiredSignature => error
    puts "JWT error: #{error.message}"
  end

  def save_token
    JwtAllowlist.new.save(@user_id, @token)
  end

  def revoke_token
    JwtAllowlist.new.revoke(@user_id, @token)
  end

  def revoke_all_tokens
    JwtAllowlist.new.revoke_all(@user_id, @token)
  end

  def revoke_all_tokens_by_id(user_id)
    JwtAllowlist.new.revoke_all_by_id(user_id)
  end

  private

  def jwt_secret
    Rails.application.credentials.jwt_secret
  end
end
