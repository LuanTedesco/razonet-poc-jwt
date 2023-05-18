class ApplicationController < ActionController::API
  before_action :authorized

  def encode_token(payload)
    exp = Time.now.to_i + 4 * 3600
    exp_payload = { data: 'data', exp: exp, user_id: payload[:user_id] }

    JWT.encode(exp_payload, Rails.application.credentials.jwt_secret, 'HS256')
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
    return unless decoded_token && decoded_token[0]['exp'] > Time.now.to_i

    user_id = decoded_token[0]['user_id']
    @user = User.find_by(id: user_id)
  end

  def logged_in?
    !!current_user
  end

  def authorized
    render json: { message: 'Please log in' }, status: :unauthorized unless logged_in?
  end
end
