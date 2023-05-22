module Api
  module V1
    class AuthController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :set_token, only: [:destroy_session, :destroy_all_sessions]

      def create
        user = User.find_by(username: user_login_params[:username])

        if user && user.authenticate(user_login_params[:password])
          token = encode_token({ user_id: user.id })

          save_token(token, user.id)
          render json: { user: UserSerializer.new(user), token: token }, status: :accepted
        else
          render json: { message: 'Invalid username or password' }, status: :unauthorized
        end
      end

      def destroy_session
        return unless auth_header

        revoke_token
        render json: { message: 'Session Destroyed Successfully' }, status: :accepted
      end

      def destroy_all_sessions
        return unless auth_header

        revoke_all_tokens
        render json: { message: 'All Sessions Destroyed Successfully' }, status: :accepted
      end

      private

      def user_login_params
        params.permit(:username, :password, auth: {})
      end
    end
  end
end