require 'securerandom'

module Api
  module V1
    class AuthPhoneController < ApiController
      before_action :verify_pin, only: %i[login_pin]
      skip_before_action :authorized, only: %i[login_pin create]

      def create
        if Phonelib.valid?(user_params[:phone])
          pin = generate_pin
          JwtPin.new.save_pin(user_params[:phone], pin)
          render json: { message: 'Send pin to whatsapp', pin: }, status: :ok
        else
          render json: { error: 'Invalid phone number' }, status: :unprocessable_entity
        end
      end

      def login_pin
        user = User.find_by(phone: user_params[:phone].slice(4, 9))

        if user
          token = generate_token(user)
          save_token(token)

          render json: { message: 'Login successful', token:, user: UserSerializer.new(user) }, status: :ok
        else
          render json: { error: 'User not found' }, status: :unprocessable_entity
        end
      end

      private

      def verify_pin
        return if JwtPin.new.is_valid?(user_params[:phone], user_params[:pin])

        render json: { error: 'Invalid pin' }, status: :unprocessable_entity
      end

      def generate_pin
        rand(100_000..999_999)
      end

      def generate_token(user)
        payload = {
          user_id: user.id,
          ip_address: user_params[:ip_address],
          date: Time.zone.now
        }
        TokenManager.new(payload:).encode_token
      end

      def save_token(token)
        TokenManager.new(token:).save_token
      end

      def user_params
        params.require(:auth).permit(:phone, :pin, :ip_address, :user_id)
      end
    end
  end
end
