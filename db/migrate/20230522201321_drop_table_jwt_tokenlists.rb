class DropTableJwtTokenlists < ActiveRecord::Migration[7.0]
  def change
    drop_table :jwt_tokenlists
  end
end
