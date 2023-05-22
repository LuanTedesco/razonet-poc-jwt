Rails.application.routes.draw do
  namespace :api do
    namespace :v1, path: 'auth' do
      resources :users, only: [:create]
      post '/login', to: 'auth#create'
      get '/logout', to: 'auth#destroy_session'
      get '/user', to: 'users#profile'
    end
  end
end
