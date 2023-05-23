class UserSerializer < ActiveModel::Serializer
  attributes :username, :email, :role
end