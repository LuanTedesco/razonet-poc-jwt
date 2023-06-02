module Api
  class ApiController < ApplicationController
    before_action :authorized

    def authorized
      set_token
      return if SessionManager.new(token: @token).logged_in?

      render json: {
        message: 'Please login'
      }, status: :unauthorized
    end

    private

    def set_token
      return unless auth_header

      @token ||= auth_header.split(' ').last
    end

    def auth_header
      request.headers['Authorization']
    end

    def client_ip
      request.remote_ip
    end

    def render_success(message, options = {})
      render json: { message: }.merge(options), status: :ok
    end

    def render_error(message, options = {})
      render json: { error: message }.merge(options), status: :unprocessable_entity
    end

    def has_timeout?
      return unless FailedLoginAttempts.new(user_ip: client_ip).exceeded?

      render_error(
        'Too many failed login attempts',
        timeout_seconds: FailedLoginAttempts.new(user_ip: client_ip).timeout
      )
    end

    def handle_invalid_credentials(message, user_id)
      LoginManager.increment_failed_attempts(client_ip)
      LoginManager.set_timeout(user_id, client_ip)
      return if has_timeout?

      render_error(
        message,
        remaining_attempts: LoginManager.remaining_attempts(client_ip)
      )
    end
  end
end
