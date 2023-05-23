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
  end
end
