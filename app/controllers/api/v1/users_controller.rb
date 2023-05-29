module Api
  module V1
    class UsersController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :set_token, only: %i[profile update destroy]

      def profile
        decoded_token = TokenManager.new(token: @token).decoded_token.first
        render json: {
          user: {
            profile: UserSerializer.new(SessionManager.new(token: @token).current_user),
            session: {
              ip_address: decoded_token['ip_address'],
              date: decoded_token['date'],
            }
          },
          token: @token
        }, status: :accepted
      end

      def create
        user = User.create(user_params)
        if user.valid?
          render json: { message: 'User created successfully', message: UserSerializer.new(user) }, status: :created
        else
          render json: { error: 'Failed to create user' }, status: :not_acceptable
        end
      end

      def update
        user = SessionManager.new(token: @token).current_user
        if user&.authenticate(user_params[:password])
          user.update(user_params)

          render json: { user: UserSerializer.new(user) }, status: :accepted
        else
          render json: { error: 'Failed to update user' }, status: :not_acceptable
        end
      end

      def destroy
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
