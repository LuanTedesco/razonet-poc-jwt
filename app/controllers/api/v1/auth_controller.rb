require './app/services/token_manager'

module Api
  module V1
    class AuthController < ApiController
      skip_before_action :authorized, only: [:create]
      before_action :set_token, only: %i[destroy_session destroy_all_sessions sessions]

      def create
        user = User.find_by(username: user_params[:username])

        if user&.authenticate(user_params[:password])
          token = TokenManager.new(payload: {
                                     user_id: user.id,
                                     ip_address: user_params[:ip_address],
                                     date: Time.zone.now
                                   }).encode_token

          TokenManager.new(token:).save_token

          render json: {
            user: {
              profile: UserSerializer.new(user),
              session: {
                ip_address: user_params[:ip_address],
                date: Time.zone.now
              }
            },
            token:
          }, status: :accepted
        else
          render json: { message: 'Invalid username or password' }, status: :unauthorized
        end
      end

      def destroy_session
        TokenManager.new(token: @token).revoke_token
        render json: { message: 'Session Destroyed Successfully' }, status: :accepted
      end

      def destroy_all_sessions
        TokenManager.new(token: @token).revoke_all_tokens
        render json: { message: 'All Sessions Destroyed Successfully' }, status: :accepted
      end

      def destroy_all_sessions_by_id
        user = SessionManager.new(token: @token).current_user
        if user.admin?
          TokenManager.new.revoke_all_tokens_by_id(user_params[:user_id])
          render json: { message: 'All Sessions Destroyed Successfully' }, status: :accepted
        else
          render json: { error: 'Unauthorized' }, status: :not_acceptable
        end
      end

      def sessions
        render json: {
          message: 'Active Sessions',
          sessions: SessionManager.new(token: @token).active_sessions
        }, status: :accepted
      end

      private

      def user_params
        params.require(:auth).permit(:username, :password, :ip_address, :user_id)
      end
    end
  end
end
