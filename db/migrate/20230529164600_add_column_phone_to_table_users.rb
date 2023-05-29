class AddColumnPhoneToTableUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :ddi_phone, :string, null: false, default: 55, limit: 3
    add_column(:users, :ddd_phone, :string, null: false, limit: 2, default: '49')
    change_column_default(:users, :ddd_phone, nil)
    add_column :users, :phone, :string, null: false, limit: 9, default: '999999999'
    change_column_default(:users, :phone, nil)
  end
end
