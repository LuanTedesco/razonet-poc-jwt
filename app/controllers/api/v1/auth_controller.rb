module Api
  module V1
    class AuthController < ApiController
      skip_before_action :authorized, only: [:create]

      def create
        @user = User.find_by(username: user_login_params[:username])
        # authenticate method comes from bcrypt
        if @user && @user.authenticate(user_login_params[:password])
          token = encode_token({ user_id: @user.id })
          render json: { user: UserSerializer.new(@user), jwt: token }, status: :accepted
        else
          render json: { message: 'Invalid username or password' }, status: :unauthorized
        end
      end

      def destroy_session
        return unless auth_header

        token = auth_header.split(' ')[1]
        revoke_token(token)
        render json: { message: 'Session Destroyed Successfully' }, status: :accepted
      end

      private

      def user_login_params
        params.permit(:username, :password, auth: {})
      end
    end
  end
end