Rails.application.routes.draw do
  namespace :api do
    namespace :v1, path: :auth do
      resources :users, only: [:create]
      post '/login', to: 'auth#create'
      get '/logout', to: 'auth#destroy_session'
      get '/logout_all', to: 'auth#destroy_all_sessions'
      get '/sessions', to: 'auth#sessions'
      get '/user', to: 'users#profile'
      put '/user', to: 'users#update'
      delete '/user', to: 'users#destroy'
    end
  end
end
