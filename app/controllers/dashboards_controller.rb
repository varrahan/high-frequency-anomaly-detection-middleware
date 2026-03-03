class DashboardsController < ApplicationController
  def show
    @anomalies        = Anomaly.recent
    @critical_count   = Anomaly.critical.count
    @total_count      = Anomaly.count
  end

  private

  def set_cable_cookie
    cookies.signed[:cable_token] = {
      value:    ENV.fetch("CABLE_TOKEN", "anonymous"),
      httponly: true,
      same_site: :strict
    }
  end
end