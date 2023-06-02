require 'phonelib'

class User < ApplicationRecord
  has_secure_password
  validates :username, uniqueness: { case_sensitive: false }
  validates :email, uniqueness: { case_sensitive: false }
  validates :password, presence: true
  validates :phone, uniqueness: { case_sensitive: false }, presence: true

  validate :validate_phone
  validate :strong_password

  enum :role, user: 'user', admin: 'admin', developer: 'developer', marketing: 'marketing'
  after_initialize :set_default_role, if: :new_record?
  after_initialize :explode_phone_number, if: :new_record?

  def set_default_role
    self.role ||= :user
  end

  def admin?
    self.role == 'admin'
  end

  def is_blocked?
    self.blocked == true
  end

  def explode_phone_number
    self.ddi_phone = phone.slice(0, 2)
    self.ddd_phone = phone.slice(2, 2)
    self.phone = phone.slice(4, 9)
  end

  private

  def validate_phone
    return if Phonelib.valid?(ddi_phone.to_s + ddd_phone.to_s + phone.to_s)

    errors.add(:phone, 'invalid format')
  end

  def strong_password
    return if password.match?(/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}/)
      
    errors.add(:password, "deve conter pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número e um caractere especial.") 
  end
end
