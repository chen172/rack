require "rack"
# Rack::Session::Cookie needs this but doesn't require it?
require "delegate"

# our app
app = Proc.new do |env|
  # write something to the session to create the cookie on first call
  env["rack.session"]["foo"] = "bar"
  # read session ID to trigger bug on second call
  env["rack.session"]["session_id"]
  [200, {}, ["ok"]]
end

# wrap app in cookie session middleware, with json coder
wrapped = Rack::Session::Cookie.new(app,
  secret: "foo",
  coder: Rack::Session::Cookie::Base64::JSON.new)

# first call to get a cookie
env = {}
status, headers, body = wrapped.call(env)
cookie = headers["Set-Cookie"].split(";").first

# trigger the bug
env = {"HTTP_COOKIE" => cookie}
wrapped.call(env)
