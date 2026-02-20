class DashboardsController < ApplicationController
  def show
    @anomalies        = Anomaly.recent
    @critical_count   = Anomaly.critical.count
    @total_count      = Anomaly.count
  end
end