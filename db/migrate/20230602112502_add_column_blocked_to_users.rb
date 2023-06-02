class AddColumnBlockedToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :blocked, :boolean, default: false
  end
end
