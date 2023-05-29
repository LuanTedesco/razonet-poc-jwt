require 'securerandom'

module Api
  module V1
    class AuthPhoneController < ApiController
      skip_before_action :authorized, only: [:create]

      def generate_pin
        pin = rand(100_000..999_999)
      end

      def create
        if Phonelib.valid?(params[:auth][:phone])
          pin = generate_pin
          JwtPin.new.save_pin(params[:auth][:phone], pin)
          render json: { pin: }, status: :ok
        else
          render json: { error: 'Invalid phone number' }, status: :unprocessable_entity
        end
      end

      private

      def user_login_params
        params.require(:auth).permit(:phone, :ip_address, :user_id)
      end
    end
  end
end
