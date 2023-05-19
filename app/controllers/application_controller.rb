class ApplicationController < ActionController::API
  before_action :authorized

  def encode_token(payload)
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
    rescue StandardError => e
      puts e
    end
  end

  def current_user
    return unless decoded_token && is_revoked?

    user_id = decoded_token[0]['user_id']
    @user = User.find_by(id: user_id)
  end

  def logged_in?
    !!current_user
  end

  def authorized
    render json: { message: 'Please log in' }, status: :unauthorized unless logged_in?
  end

  def revoke_token(token)
    expiration = 24.hours.to_i # Set the expiration time as per your requirements

    begin
      JwtBlacklist.new.revoke(token, expiration)
    rescue => exception
      nil
    end
    # Handle the response accordingly
  end

  def is_revoked?
    if JwtBlacklist.new.revoked?(request.headers['Authorization'])
      render json: { error: 'Token revoked' }, status: :unauthorized
    else
      # some action maybe
    end
  end
end
