# authlogic.rb
# from Aaron Massey

# TODO: Setup Cucumber files to test the authentication system
# TODO: Add OpenID support
# TODO: Clean up the kludge of creating files and moving them around

# Delete unnecessary files
  run "rm README"
  run "rm public/index.html"
  run "rm public/favicon.ico"
  
# Copy database.yml for distribution use
  run "cp config/database.yml config/database.yml.example"
  
# Set up .gitignore files
  run "touch tmp/.gitignore log/.gitignore vendor/.gitignore"
  run %{find . -type d -empty | grep -v "vendor" | grep -v ".git" | grep -v "tmp" | xargs -I xxx touch xxx/.gitignore}
  file '.gitignore', <<-END
.DS_Store
log/*.log
tmp/**/*
config/database.yml
db/*.sqlite3
END

# Install submoduled plugins
  # plugin 'asset_packager', :git => 'git://github.com/sbecker/asset_packager.git', :submodule => true
  # plugin 'acts_as_taggable_redux', :git => 'git://github.com/monki/acts_as_taggable_redux.git', :submodule => true
  # plugin 'aasm', :git => 'git://github.com/rubyist/aasm.git', :submodule => true

# Install useful gems
  gem 'thoughtbot-factory_girl', :lib => 'factory_girl', :source => 'http://gems.github.com'
  # gem 'ruby-openid', :lib => 'openid'
  gem "rspec", :lib => false, :version => ">=1.2.2"
  gem "rspec-rails", :lib => false, :version => ">=1.2.2"
  gem "webrat", :lib => false, :version => ">=0.4.3"
  gem "cucumber", :lib => false, :version => ">=0.3.0"
  gem 'authlogic', :lib => false
  rake('gems:install', :sudo => true)

# Set up sessions, RSpec, user model, OpenID, etc, and run migrations
  generate("session", "user_session")
  generate("model", "user", "username:string", "email:string", "crypted_password:string", "password_salt:string", "persistence_token:string", "single_access_token:string", "perishable_token:string", "login_count:integer", "failed_login_count:integer", "last_request_at:datetime", "current_login_at:datetime", "last_login_at:datetime", "current_login_ip:string", "last_login_ip:string")
  file 'temp', <<-TEMP
class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string    :login,               :null => false                # optional, you can use email instead, or both
      t.string    :email,               :null => false                # optional, you can use login instead, or both
      t.string    :crypted_password,    :null => false                # optional, see below
      t.string    :password_salt,       :null => false                # optional, but highly recommended
      t.string    :persistence_token,   :null => false                # required
      t.string    :single_access_token, :null => false                # optional, see Authlogic::Session::Params
      t.string    :perishable_token,    :null => false                # optional, see Authlogic::Session::Perishability

      # Magic columns, just like ActiveRecord's created_at and updated_at. These are automatically maintained by Authlogic if they are present.
      t.integer   :login_count,         :null => false, :default => 0 # optional, see Authlogic::Session::MagicColumns
      t.integer   :failed_login_count,  :null => false, :default => 0 # optional, see Authlogic::Session::MagicColumns
      t.datetime  :last_request_at                                    # optional, see Authlogic::Session::MagicColumns
      t.datetime  :current_login_at                                   # optional, see Authlogic::Session::MagicColumns
      t.datetime  :last_login_at                                      # optional, see Authlogic::Session::MagicColumns
      t.string    :current_login_ip                                   # optional, see Authlogic::Session::MagicColumns
      t.string    :last_login_ip                                      # optional, see Authlogic::Session::MagicColumns

      t.timestamps
    end
  end

  def self.down
    drop_table :users
  end
end
TEMP
  run "mv temp `find . -name *_create_users.rb -type f -print0`"
  file 'temp', <<-TEMP
class User < ActiveRecord::Base
  acts_as_authentic
end
TEMP
  run "mv temp `find . -name user.rb -type f -print0`"
  generate("controller", "user_sessions")
  route "map.resource :user_session"
  route "map.root :controller => 'user_sessions', :action => 'new' # optional, this just sets the root route"
  route "map.resource :account, :controller => 'users'"
  route "map.resources :users"
  file 'temp', <<-TEMP
class ApplicationController < ActionController::Base
  helper :all
  helper_method :current_user_session, :current_user
  filter_parameter_logging :password, :password_confirmation
  
  private
    def current_user_session
      return @current_user_session if defined?(@current_user_session)
      @current_user_session = UserSession.find
    end
    
    def current_user
      return @current_user if defined?(@current_user)
      @current_user = current_user_session && current_user_session.record
    end
    
    def require_user
      unless current_user
        store_location
        flash[:notice] = "You must be logged in to access this page"
        redirect_to new_user_session_url
        return false
      end
    end
 
    def require_no_user
      if current_user
        store_location
        flash[:notice] = "You must be logged out to access this page"
        redirect_to account_url
        return false
      end
    end
    
    def store_location
      session[:return_to] = request.request_uri
    end
    
    def redirect_back_or_default(default)
      redirect_to(session[:return_to] || default)
      session[:return_to] = nil
    end
end
TEMP
  run "mv temp `find . -name application_controller.rb -type f -print0`"
  generate("rspec")
  generate("cucumber")
  generate("nifty_layout")
  # rake('acts_as_taggable:db:create')
  rake('db:migrate')

# Set up session store initializer
  initializer 'session_store.rb', <<-END
ActionController::Base.session = { :session_key => '_#{(1..6).map { |x| (65 + rand(26)).chr }.join}_session', :secret => '#{(1..40).map { |x| (65 + rand(26)).chr }.join}' }
ActionController::Base.session_store = :active_record_store
  END
 
# Commit all work so far to the repository
  git :init
  git :add => '.'
  git :commit => "-a -m 'Initial commit'"

# Success!
  puts "Success!"