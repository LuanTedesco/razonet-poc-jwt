require './app/services/token_manager'

module Api
  module V1
    class AuthController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :has_timeout?, only: %i[create]
      before_action :set_token, only: %i[destroy_session destroy_all_sessions sessions]
      before_action :user_exists?, only: [:create]
      before_action :login_is_blocked?, only: [:create]

      def create
        if @user&.authenticate(user_params[:password])
          token = LoginManager.generate_token(@user, client_ip)
          LoginManager.save_token(token)

          LoginManager.reset_failed_attempts(client_ip)
          render_success('Login Successful', user: { profile: UserSerializer.new(@user) }, token:)
        else
          handle_invalid_credentials('Invalid Password', @user.id)
        end
      end

      def destroy_session
        TokenManager.new(token: @token).revoke_token
        render_success('Session Destroyed Successfully')
      end

      def destroy_all_sessions
        TokenManager.new(token: @token).revoke_all_tokens
        render_success('All Sessions Destroyed Successfully')
      end

      def destroy_all_sessions_by_id
        user = SessionManager.new(token: @token).current_user
        if user.admin?
          TokenManager.new.revoke_all_tokens_by_id(user_params[:user_id])
          render_success('All Sessions Destroyed Successfully')
        else
          render_error('Unauthorized')
        end
      end

      def sessions
        render_success('Active Sessions', sessions: SessionManager.new(token: @token).active_sessions)
      end

      private

      def user_params
        params.require(:auth).permit(:username, :password, :user_id)
      end

      def user_exists?
        return if @user = User.find_by(username: user_params[:username])

        render_error('Invalid Username')
      end

      def login_is_blocked?
        return unless @user.is_blocked?

        render_error('Account BLOCKED because due to too many attempts. Please, contact support.')
      end
    end
  end
end
