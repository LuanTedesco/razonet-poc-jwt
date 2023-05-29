class UserSerializer < ActiveModel::Serializer
  attributes :username, :email, :role, :ddi_phone, :ddd_phone, :phone
end
