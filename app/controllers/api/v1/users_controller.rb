module Api
  module V1
    class UsersController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :set_token, only: %i[profile update destroy]

      def profile
        render json: { user: UserSerializer.new(SessionManager.new(token: @token).current_user) }, status: :accepted
      end

      def create
        user = User.create(user_params)
        if user.valid?
          token = TokenManager.new(payload: { user_id: user.id }).encode_token

          TokenManager.new(token: token).save_token
          render json: { user: UserSerializer.new(user), token: token }, status: :created
        else
          render json: { error: 'Failed to create user' }, status: :not_acceptable
        end
      end

      def update
        return unless auth_header

        user = SessionManager.new(token: @token).current_user
        if user&.authenticate(user_params[:password])
          user.update(user_params)

          render json: { user: UserSerializer.new(user) }, status: :accepted
        else
          render json: { error: 'Failed to update user' }, status: :not_acceptable
        end
      end

      def destroy
        return unless auth_header

        user = SessionManager.new(token: @token).current_user
        if user&.authenticate(user_params[:password])
          user.destroy

          TokenManager.new(token: @token).revoke_token
          render json: { message: 'User deleted successfully' }, status: :accepted
        else
          render json: { error: 'Failed to delete user' }, status: :not_acceptable
        end
      end

      private

      def user_params
        params.require(:user).permit(:username, :email, :password)
      end
    end
  end
end
