class CreateJwtTokenlists < ActiveRecord::Migration[7.0]
  def change
    create_table :jwt_tokenlists do |t|
      t.string :jti, null: false
      t.bigint :exp, null: false
      t.boolean :revoked,  default: false

      t.timestamps
      t.references :user, index: true
    end
  end
end
