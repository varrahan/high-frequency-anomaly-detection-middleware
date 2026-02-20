module Api
  module V1
    class AnomaliesController < ApplicationController
      before_action :authenticate_worker!

      skip_before_action :verify_authenticity_token

      def create
        @anomaly = Anomaly.new(anomaly_params)

        if @anomaly.save
          render json: { status: "created", id: @anomaly.id },
                 status: :created
        else
          render json: { status: "error", errors: @anomaly.errors.full_messages },
                 status: :unprocessable_entity
        end
      end

      private

      def anomaly_params
        params.require(:anomaly).permit(
          :source_ip,
          :destination_ip,
          :protocol,
          :severity,
          :score,
          :description,
          :raw_payload,
          :detected_at
        )
      end

      def authenticate_worker!
        token = request.headers["X-Worker-Token"]
        expected = ENV.fetch("ANOMALY_WORKER_TOKEN", "dev-secret-change-me")

        unless ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected)
          render json: { error: "unauthorized" }, status: :unauthorized
        end
      end
    end
  end
end