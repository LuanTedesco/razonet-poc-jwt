module Api
  module V1
    class UsersController < ApiController
      skip_before_action :authorized, only: [:create]

      def profile
        render json: { user: UserSerializer.new(current_user) }, status: :accepted
      end

      def create
        user = User.create(user_params)
        if user.valid?
          token = TokenManager.encode_token(user_id: user.id)

          TokenManager.save_token(token, user.id)
          render json: { user: UserSerializer.new(user), token: token }, status: :created
        else
          render json: { error: 'Failed to create user' }, status: :not_acceptable
        end
      end

      private

      def user_params
        params.require(:user).permit(:username, :email, :password)
      end
    end
  end
end