# rename to config.ru
## mv test_rack_use.rb config.ru
# run app
## rackup

class Middleware
  def initialize(app)
    puts "in initializee"
    @app = app
  end

  def call(env)
    puts "in call"
    env["rack.some_header"] = "setting an example"
    @app.call(env)
  end
end

  puts "before Middleware"
  use Middleware
  puts "after Middleware"
  run lambda { |env| [200, {"Content-Type" => "text/plain"}, ["OK"]]}
  
