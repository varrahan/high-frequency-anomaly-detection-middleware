class CreateAnomalies < ActiveRecord::Migration[7.1]
  def change
    create_table :anomalies do |t|
      t.string  :source_ip,      null: false
      t.string  :destination_ip
      t.string  :protocol,       limit: 16

      t.string  :severity,       null: false
      t.decimal :score,          null: false, precision: 8, scale: 6
      t.text    :description,    null: false
      t.text    :raw_payload
      t.datetime :detected_at
      t.timestamps null: false
    end

    add_index :anomalies, :created_at
    add_index :anomalies, :severity
    add_index :anomalies, [:source_ip, :severity]
  end
end