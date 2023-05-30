Rails.application.routes.draw do
  namespace :api do
    namespace :v1, path: :auth do
      resources :users, only: [:create]
      post '/login', to: 'auth#create'
      post '/login_phone', to: 'auth_phone#create'
      post '/login_pin', to: 'auth_phone#login_pin'
      get '/logout', to: 'auth#destroy_session'
      get '/logout_all', to: 'auth#destroy_all_sessions'
      get '/sessions', to: 'auth#sessions'
      get '/user', to: 'users#profile'
      put '/user', to: 'users#update'
      delete '/user', to: 'users#destroy'
      post '/logout_all_by_id', to: 'auth#destroy_all_sessions_by_id'
    end
  end
end
