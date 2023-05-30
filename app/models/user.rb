require 'phonelib'

class User < ApplicationRecord
  has_secure_password
  validates :username, uniqueness: { case_sensitive: false }
  validates :email, uniqueness: { case_sensitive: false }
  validates :phone, presence: true

  validate :validate_phone

  enum :role, user: 'user', admin: 'admin', developer: 'developer', marketing: 'marketing'
  after_initialize :set_default_role, if: :new_record?
  before_validation :explode_phone_number

  def set_default_role
    self.role ||= :user
  end

  def admin?
    self.role == 'admin'
  end

  def explode_phone_number
    self.ddi_phone = phone.slice(0, 2)
    self.ddd_phone = phone.slice(2, 2)
    self.phone = phone.slice(4, 9)
  end

  private

  def validate_phone
    unless Phonelib.valid?(self.ddi_phone.to_s + self.ddd_phone.to_s + self.phone.to_s)
      errors.add(:phone, "Formato inválido")
    end
  end
end
