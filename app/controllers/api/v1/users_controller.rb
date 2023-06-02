module Api
  module V1
    class UsersController < ApiController
      skip_before_action :authorized, only: %i[create user_list]
      before_action :set_token, only: %i[profile update destroy]

      def profile
        decoded_token = TokenManager.new(token: @token).decoded_token.first
        render_success('User', user: {
                                 profile: UserSerializer.new(current_user),
                                 session: {
                                   ip_address: decoded_token['ip_address'],
                                   date: decoded_token['date']
                                 }
                               },
                               token: @token)
      end

      def create
        user = User.create(user_params)
        if user.valid?
          render_success('User created successfully', user: UserSerializer.new(user))
        else

          render_error('Failed to create user', errors: user.errors.full_messages)
        end
      end

      def update
        user = SessionManager.new(token: @token).current_user
        if user&.authenticate(user_params[:password])
          user.update(user_params)

          render_success('User updated successfully', user: UserSerializer.new(user))
        else
          render_error('Failed to update user', errors: user.errors.full_messages)
        end
      end

      def destroy
        user = SessionManager.new(token: @token).current_user
        if user&.authenticate(user_params[:password])
          user.destroy

          TokenManager.new(token: @token).revoke_token
          render_success('User deleted successfully')
        else
          render_error('Failed to delete user', user.errors.full_messages)
        end
      end

      def user_list
        render_success('User', users: User.all)
      end

      private

      def user_params
        params.require(:user).permit(:username, :email, :phone, :password)
      end

      def current_user
        SessionManager.new(token: @token).current_user
      end
    end
  end
end
