require './app/services/session_manager'

module Api
  class ApiController < ApplicationController
    before_action :authorized
    before_action :set_token

    def authorized
      render json: { message: 'Please login' }, status: :unauthorized unless SessionManager.logged_in?(token: @token)
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
