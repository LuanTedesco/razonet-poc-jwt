class ChangeColumnPhoneToDefault < ActiveRecord::Migration[7.0]
  def change
    change_column_default(:users, :phone, nil)
  end
end
