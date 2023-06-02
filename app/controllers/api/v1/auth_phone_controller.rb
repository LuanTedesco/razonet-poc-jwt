module Api
  module V1
    class AuthPhoneController < ApiController
      before_action :has_timeout?, only: %i[login_pin]
      before_action :verify_pin, only: %i[login_pin]
      before_action :valid_phone?, only: %i[create_pin login_pin]
      before_action :user_exists?, only: %i[create_pin login_pin]
      before_action :login_is_blocked?, only: %i[create_pin login_pin]
      skip_before_action :authorized, only: %i[create_pin login_pin]

      def create_pin
        if @user
          pin = generate_pin
          save_pin(user_params[:phone], pin)
          render_success('PIN sent by WhatsApp', pin:)
        else
          render_error('Error sending PIN')
        end
      end

      def login_pin
        if @user
          token = LoginManager.generate_token(@user, client_ip)
          LoginManager.save_token(token)
          LoginManager.reset_failed_attempts(client_ip)
          JwtPin.new.revoke_pin(user_params[:phone])
          render_success('Login successful', token:, user: UserSerializer.new(@user))
        else
          handle_invalid_credentials('Invalid PIN', @user.id)
        end
      end

      private

      def user_params
        params.require(:auth).permit(:phone, :pin)
      end

      def verify_pin
        return if JwtPin.new.is_correct?(user_params[:phone], user_params[:pin])

        render_error('Invalid PIN')
      end

      def generate_pin
        rand(100_000..999_999)
      end

      def save_pin(phone, pin)
        JwtPin.new.save_pin(phone, pin)
      end

      def user_exists?
        return if @user = User.find_by(phone: user_params[:phone].to_s.slice(4, 9))

        render_error('User not found')
      end

      def valid_phone?
        return if Phonelib.valid?(user_params[:phone])

        render_error('Invalid Phone Number')
      end

      def login_is_blocked?
        return unless @user.is_blocked?

        render_error('Account BLOCKED because due to too many attempts. Please, contact support.')
      end
    end
  end
end
