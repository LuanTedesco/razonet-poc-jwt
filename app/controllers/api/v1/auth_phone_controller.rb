module Api
  module V1
    class AuthPhoneController < ApiController
      before_action :has_timeout?, only: %i[login_pin]
      before_action :verify_pin, only: %i[login_pin]
      before_action :user_exists?, only: %i[create login_pin]
      skip_before_action :authorized, only: %i[login_pin create]

      def create
        if Phonelib.valid?(user_params[:phone]) && !!user_exists?
          JwtPin.new.save_pin(user_params[:phone], generate_pin)

          render json: { message: 'PIN sent by WhatsApp'}, status: :ok
        else
          FailedLoginAttempts.new(user_ip: client_ip).increment
          render json: {
            error: 'Invalid phone number'
          }, status: :unprocessable_entity
        end
      end

      def login_pin
        if !!user_exists?
          token = generate_token(user_exists?)
          save_token(token)
          FailedLoginAttempts.new(user_ip: client_ip).reset
          render json: { message: 'Login successfuly', token:, user: UserSerializer.new(user_exists?) }, status: :ok
        else
          FailedLoginAttempts.new(user_ip: client_ip).increment
          set_login_timeout
          has_timeout?
          render json: {
            error: 'User not found',
            remaining_attempts: FailedLoginAttempts.new(user_ip:client_ip).remaining_attempts
          }, status: :unprocessable_entity
        end
      end

      private

      def verify_pin
        return if JwtPin.new.is_valid?(user_params[:phone], user_params[:pin])

        FailedLoginAttempts.new(user_ip: client_ip).increment
        set_login_timeout
        render json: {
          error: 'Invalid pin',
          remaining_attempts: FailedLoginAttempts.new(user_ip:client_ip).remaining_attempts
        }, status: :unprocessable_entity
      end

      def generate_pin
        rand(100_000..999_999)
      end

      def generate_token(user)
        payload = {
          user_id: user.id,
          ip_address: client_ip,
          date: Time.zone.now
        }
        TokenManager.new(payload:).encode_token
      end

      def save_token(token)
        TokenManager.new(token:).save_token
      end

      def user_exists?
        User.find_by(phone: user_params[:phone].slice(4, 9))
      end

      def user_params
        params.require(:auth).permit(:phone, :pin, :user_id)
      end

      def has_timeout?
        return unless FailedLoginAttempts.new(user_ip: client_ip).exceeded?

        render json: {
          error: 'Too many failed login attempts',
          timeout_seconds: FailedLoginAttempts.new(user_ip: client_ip).timeout.to_s
        }, status: :unprocessable_entity
      end

      def set_login_timeout
        case FailedLoginAttempts.new(user_ip: client_ip).attempts
        when 5
          FailedLoginAttempts.new(user_ip: client_ip, timeout: 30.minutes.to_i).set_login_timeout
        when 10
          FailedLoginAttempts.new(user_ip: client_ip, timeout: 2.hours.to_i).set_login_timeout
        when 15
          FailedLoginAttempts.new(user_ip: client_ip, timeout: 24.hours.to_i).set_login_timeout
        when >= 20
          puts 'Account BLOCKED because due to too many attempts, contact support'
        else
          puts 'No action'
        end
      end
    end
  end
end
