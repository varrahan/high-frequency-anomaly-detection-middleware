class Anomaly < ApplicationRecord
  validates :source_ip,   presence: true
  validates :severity,    presence: true, inclusion: { in: %w[low medium high critical] }
  validates :score,       presence: true, numericality: { greater_than_or_equal_to: 0.0, less_than_or_equal_to:    1.0 }
  validates :description, presence: true

  before_create -> { self.detected_at ||= Time.current }
  after_create_commit :broadcast_anomaly

  scope :critical, -> { where(severity: "critical") }
  scope :recent,   -> { order(created_at: :desc).limit(100) }

  private

  def broadcast_anomaly(
    broadcast_prepend_to  
      "anomalies", 
      target: "anomalies_list",  
      partial: "anomalies/anomaly", 
      locals:  { anomaly: self }
    )
  end
end