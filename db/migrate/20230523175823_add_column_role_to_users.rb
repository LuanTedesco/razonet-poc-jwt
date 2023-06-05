class AddColumnRoleToUsers < ActiveRecord::Migration[7.0]
  def change
    create_enum :role, %w[user admin developer marketing]
    add_column :users, :role, :enum, enum_type: :role, default: 'user', null: false
  end
end
