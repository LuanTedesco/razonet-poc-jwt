class User < ApplicationRecord
  has_secure_password
  validates :username, uniqueness: { case_sensitive: false }
  validates :email, uniqueness: { case_sensitive: false }

  enum :role, user: 'user', admin: 'admin', developer: 'developer', marketing: 'marketing'
  after_initialize :set_default_role, if: :new_record?

  def set_default_role
    self.role ||= :user
  end

  def admin?
    self.role == 'admin'
  end
end
