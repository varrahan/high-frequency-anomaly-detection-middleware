Rails.application.routes.draw do

  root "dashboards#show"
  namespace :api do
    namespace :v1 do
      resources :anomalies, only: [:create]
    end
  end

  mount ActionCable.server => "/cable"
end