require './app/services/token_manager'

module Api
  module V1
    class AuthController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :set_token, only: %i[destroy_session destroy_all_sessions sessions]

      def create
        user = User.find_by(username: user_login_params[:username])

        if user&.authenticate(user_login_params[:password])
          token = TokenManager.new(payload: { user_id: user.id }).encode_token

          TokenManager.new(token: token).save_token
          render json: { user: UserSerializer.new(user), token: token }, status: :accepted
        else
          render json: { message: 'Invalid username or password' }, status: :unauthorized
        end
      end

      def destroy_session
        return unless auth_header

        TokenManager.new(token: @token).revoke_token
        render json: { message: 'Session Destroyed Successfully' }, status: :accepted
      end

      def destroy_all_sessions
        return unless auth_header

        TokenManager.new(token: @token).revoke_all_tokens
        render json: { message: 'All Sessions Destroyed Successfully' }, status: :accepted
      end

      def sessions
        return unless auth_header

        render json: {
          message: 'Active Sessions',
          sessions: SessionManager.new(token: @token).active_sessions
        }, status: :accepted
      end

      private

      def user_login_params
        params.permit(:username, :password, auth: {})
      end
    end
  end
end
