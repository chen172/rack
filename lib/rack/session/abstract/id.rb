# frozen_string_literal: true

# AUTHOR: blink <blinketje@gmail.com>; blink#ruby-lang@irc.freenode.net
# bugrep: Andreas Zehnder

require_relative '../../../rack'
require 'time'
require 'securerandom'
require 'digest/sha2'

module Rack

  module Session

    class SessionId
      ID_VERSION = 2

      attr_reader :public_id

      # 初始化public_id
      def initialize(public_id)
        @public_id = public_id
      end

      def private_id
        "#{ID_VERSION}::#{hash_sid(public_id)}"
      end

      alias :cookie_value :public_id
      alias :to_s :public_id

      def empty?; false; end
      def inspect; public_id.inspect; end

      private

      # Digest::SHA256.hexdigest 'abc'        # => "ba7816bf8..."
      # 转化session id
      def hash_sid(sid)
        Digest::SHA256.hexdigest(sid)
      end
    end

    module Abstract
      # SessionHash is responsible to lazily load the session from store.

      # 给头部rack.session设置为这个
      class SessionHash
        include Enumerable
        attr_writer :id

        Unspecified = Object.new

        # 得到客户端请求的头部rack.session
        def self.find(req)
          req.get_header RACK_SESSION
        end

        # 给客户端请求的头部rack.session 设置session
        def self.set(req, session)
          req.set_header RACK_SESSION, session
        end

        # 给客户端请求的头部rack.session.options 设置options
        def self.set_options(req, options)
          req.set_header RACK_SESSION_OPTIONS, options.dup
        end

        # store是Persisted instance
        # 初始化，设置变量
        # 初始化时是没有加载session, 加载状态设置为false
        def initialize(store, req)
          @store = store
          @req = req
          @loaded = false
        end

        # 如果session加载了或者@id存在，就返回@id
        def id
          return @id if @loaded or instance_variable_defined?(:@id)
          # 调用Persisted instance的方法extract_session_id来得到session id
          @id = @store.send(:extract_session_id, @req)
        end

        # 得到客户端的请求头部rack.session.options
        def options
          @req.session_options
        end

        def each(&block)
          load_for_read!
          @data.each(&block)
        end

        # 得到session hash的某个字段
        def [](key)
          load_for_read!
          @data[key.to_s]
        end

        def dig(key, *keys)
          load_for_read!
          @data.dig(key.to_s, *keys)
        end

        def fetch(key, default = Unspecified, &block)
          load_for_read!
          if default == Unspecified
            @data.fetch(key.to_s, &block)
          else
            @data.fetch(key.to_s, default, &block)
          end
        end

        # 判断session hash是否存在某个字段
        def has_key?(key)
          load_for_read!
          @data.has_key?(key.to_s)
        end
        alias :key? :has_key?
        alias :include? :has_key?

        # 往session hash写入某个字段
        def []=(key, value)
          load_for_write!
          @data[key.to_s] = value
        end
        alias :store :[]=

        # 清除session hash
        def clear
          load_for_write!
          @data.clear
        end

        def destroy
          clear
          # 调用Persisted instance的方法delete_session来destroy session id
          @id = @store.send(:delete_session, @req, id, options)
        end

        def to_hash
          load_for_read!
          @data.dup
        end

        def update(hash)
          load_for_write!
          @data.update(stringify_keys(hash))
        end
        alias :merge! :update

        def replace(hash)
          load_for_write!
          @data.replace(stringify_keys(hash))
        end

        def delete(key)
          load_for_write!
          @data.delete(key.to_s)
        end

        def inspect
          if loaded?
            @data.inspect
          else
            "#<#{self.class}:0x#{self.object_id.to_s(16)} not yet loaded>"
          end
        end

        def exists?
          return @exists if instance_variable_defined?(:@exists)
          @data = {}
          @exists = @store.send(:session_exists?, @req)
        end

        # 是否加载了session, 得到@loaded变量
        def loaded?
          @loaded
        end

        # session是不是空的
        def empty?
          # 加载session
          load_for_read!
          # 是否加载到了session数据
          @data.empty?
        end

        def keys
          load_for_read!
          @data.keys
        end

        def values
          load_for_read!
          @data.values
        end

      private

        # 下面两个方法都是加载session
        def load_for_read!
          # 如果session还没有加载并且存在session,就加载它
          load! if !loaded? && exists?
        end

        def load_for_write!
          # 如果没有加载session,就加载它
          load! unless loaded?
        end

        # 确定加载session,再这里就有了session数据
        def load!
          # @store是class Persisted
          # 还是要通过Persisted instance的load_session方法来加载session id
          # 然后就可以得到session id, session data, session的加载状态也设为true
          @id, session = @store.send(:load_session, @req)
          # 字符串化session数据
          @data = stringify_keys(session)
          # 加载session的状态设置为true
          @loaded = true
        end

        # 字符串化Hash
        def stringify_keys(other)
          # Use transform_keys after dropping Ruby 2.4 support
          hash = {}
          other.to_hash.each do |key, value|
            hash[key.to_s] = value
          end
          hash
        end
      end

      # ID sets up a basic framework for implementing an id based sessioning
      # service. Cookies sent to the client for maintaining sessions will only
      # contain an id reference. Only #find_session, #write_session and
      # #delete_session are required to be overwritten.
      #
      # ID sets up了一个基本的框架用来实现一个基于id的sessioning服务。
      # 发送给客户端的cookie用来维持sessions将只会包含一个id参考值。
      # 只有find_session, write_session, delete_session需要重写。
      
      # All parameters are optional.
      # * :key determines the name of the cookie, by default it is
      #   'rack.session'
      # * :path, :domain, :expire_after, :secure, :httponly, and :same_site set
      #   the related cookie options as by Rack::Response#set_cookie
      # * :skip will not a set a cookie in the response nor update the session state
      # * :defer will not set a cookie in the response but still update the session
      #   state if it is used with a backend
      # * :renew (implementation dependent) will prompt the generation of a new
      #   session id, and migration of data to be referenced at the new id. If
      #   :defer is set, it will be overridden and the cookie will be set.
      # * :sidbits sets the number of bits in length that a generated session
      #   id will be.
      #
      # 所有的参数都是可选的。
      # * ：key决定了cookie的名字，默认是rack.session
      # * :path, :domain, :expire_after, :secure, :httponly, :same_site
      
      # These options can be set on a per request basis, at the location of
      # <tt>env['rack.session.options']</tt>. Additionally the id of the
      # session can be found within the options hash at the key :id. It is
      # highly not recommended to change its value.
      #
      # Is Rack::Utils::Context compatible.
      #
      # Not included by default; you must require 'rack/session/abstract/id'
      # to use.

      class Persisted
        DEFAULT_OPTIONS = {
          key: RACK_SESSION,
          path: '/',
          domain: nil,
          expire_after: nil,
          secure: false,
          httponly: true,
          defer: false,
          renew: false,
          sidbits: 128,
          cookie_only: true,
          secure_random: ::SecureRandom
        }.freeze

        attr_reader :key, :default_options, :sid_secure

        # Rack::Session::Cookie初始化会调用这个方法
        # 初始化只是初始化一些变量
        def initialize(app, options = {})
          @app = app
          # 加入默认的选项
          @default_options = self.class::DEFAULT_OPTIONS.merge(options)
          # 得到key, 也就是_gh_manage
          @key = @default_options.delete(:key)
          @cookie_only = @default_options.delete(:cookie_only)
          @same_site = @default_options.delete(:same_site)
          # 初始化session id
          initialize_sid
        end

        # Rack::Session::Cookie初始化之后，就会调用call方法来处理来自客户端的请求
        def call(env)
          context(env)
        end

        def context(env, app = @app)
          # 得到来自客户端的请求
          req = make_request env
          # 对来自客户端的请求设置好了session头部
          # 设置了rack.session头部和rack.session.options头部
          # 在env中添加了rack.session和rack.session.options
          prepare_session(req)
          # 得到对客户端的响应
          # 调用app,这个时候可能设置rack.session hash
          # 给rack.session 添加session id
          status, headers, body = app.call(req.env)
          # 使用Rack::Response构造响应
          res = Rack::Response::Raw.new status, headers
          # commit_session应该是通过env的rack.session和rack.session.options构造了Set-Cookie头部
          commit_session(req, res)
          # 返回对客户端的响应
          [status, headers, body]
        end

        private

        def make_request(env)
          Rack::Request.new env
        end

        def initialize_sid
          # session id的长度，128位
          @sidbits = @default_options[:sidbits]
          @sid_secure = @default_options[:secure_random]
          # 64
          @sid_length = @sidbits / 4
        end

        # Generate a new session id using Ruby #rand.  The size of the
        # session id is controlled by the :sidbits option.
        # Monkey patch this to use custom methods for session id generation.
        # 使用rand方法生成一个新的session id。session id的长度是由sidbits选项控制的。
        
        def generate_sid(secure = @sid_secure)
          if secure
            secure.hex(@sid_length)
          else
            "%0#{@sid_length}x" % Kernel.rand(2**@sidbits - 1)
          end
        rescue NotImplementedError
          generate_sid(false)
        end

        # Sets the lazy session at 'rack.session' and places options and session
        # metadata into 'rack.session.options'.
        
        def prepare_session(req)
          # 得到客户端请求的头部RACK_SESSION,看是否设置了session
          # RACK_SESSION是rack.session
          # rack.session头部?????
          # 请求的env中是否有rack.session
          # 得到env["rack.session"]
          # 来自客户端的请求应该是没有这个头部的
          session_was               = req.get_header RACK_SESSION
          # 得到session这个instance
          # 下面的代码是session = SessionHash.new(self,req),所以它其实是初始化session hash
          session                   = session_class.new(self, req)
          # rack.session和rack.session.options都是放到了env这个hash中
          # 设置头部rack.session的值为session
          # env["rack.session"] = session
          req.set_header RACK_SESSION, session
          # 设置头部rack.session.options的值为@default_options
          # env["rack.session.options"] = @default_options
          req.set_header RACK_SESSION_OPTIONS, @default_options.dup
          # 如果客户端的请求有session的话，把session合在一起
          session.merge! session_was if session_was
        end

        # Extracts the session id from provided cookies and passes it and the
        # environment to #find_session.

        # 从客户端的请求中的cookie提取session id
        def load_session(req)
          # 从请求中得到sid
          sid = current_session_id(req)
          # 根据请求和sid得到session
          sid, session = find_session(req, sid)
          [sid, session || {}]
        end

        # Extract session id from request object.

        # 从客户端请求对象中提取session id
        def extract_session_id(request)
          # 从请求的cookies中得到sid
          sid = request.cookies[@key]
          sid ||= request.params[@key] unless @cookie_only
          sid
        end

        # Returns the current session id from the SessionHash.

        # 从SessionHash中返回当前的session id
        def current_session_id(req)
          # 从客户端请求的头部rack.session得到session id
          req.get_header(RACK_SESSION).id
        end

        # Check if the session exists or not.

        # 检查客户端请求是否存在session
        def session_exists?(req)
          value = current_session_id(req)
          value && !value.empty?
        end

        # Session should be committed if it was loaded, any of specific options like :renew, :drop
        # or :expire_after was given and the security permissions match. Skips if skip is given.

        # 如果session被加载了，它应该被提交
        # 传入的session参数是SessionHash的一个instance,只是初始化了一些变量
        def commit_session?(req, session, options)
          if options[:skip]
            false
          else
            # 加载session或者强制更新session
            # loaded_session?(session)为false,还没有加载session
            has_session = loaded_session?(session) || forced_session_update?(session, options)
            has_session && security_matches?(req, options)
          end
        end

        # 加载session,先要确保session hash是一个session class
        def loaded_session?(session)
          # session不是一个session_class或者session加载了
          # session是一个session_class,但是session还没有加载
          # 前面的判断是多余的？？？，永远为false
          !session.is_a?(session_class) || session.loaded?
        end

        def forced_session_update?(session, options)
          # session是不是空的
          force_options?(options) && session && !session.empty?
        end

        def force_options?(options)
          options.values_at(:max_age, :renew, :drop, :defer, :expire_after).any?
        end

        def security_matches?(request, options)
          return true unless options[:secure]
          request.ssl?
        end

        # Acquires the session from the environment and the session id from
        # the session options and passes them to #write_session. If successful
        # and the :defer option is not true, a cookie will be added to the
        # response with the session's id.
        # 从环境变量(env)中得到session,从session选项中得到session id,传入到write_session方法中。
        # 如果成功了，并且defer选项设置为false,一个cookie将会被添加到响应的头部中，即Set-Cookie头部
        def commit_session(req, res)
          # 得到头部rack.session
          session = req.get_header RACK_SESSION
          # 得到session选项，即头部rack.session.options
          options = session.options

          # 如果选项drop或者renew设置了
          # 默认这些都是false,也就是不会执行下面的代码
          if options[:drop] || options[:renew]
            # 重新得到一个session id
            session_id = delete_session(req, session.id || generate_sid, options)
            # 如果没有session_id，就返回
            return unless session_id
          end

          # 从客户端的请求中加载session
          return unless commit_session?(req, session, options)

          # 如果session没有加载，就加载session
          session.send(:load!) unless loaded_session?(session)
          # 加载session之后，可以得到session id
          session_id ||= session.id
          # 得到session_data
          # session_data是一个hash，包含session id
          session_data = session.to_hash.delete_if { |k, v| v.nil? }

          # 把session id和session data写到头部中
          # 得到的data是一个instance
          if not data = write_session(req, session_id, session_data, options)
            req.get_header(RACK_ERRORS).puts("Warning! #{self.class.name} failed to save session. Content dropped.")
          elsif options[:defer] and not options[:renew]
            req.get_header(RACK_ERRORS).puts("Deferring cookie for #{session_id}") if $VERBOSE
          else
            # 新建一个hash 
            cookie = Hash.new
            # 得到cookie的值，就是通过这个值来管理session会话
            cookie[:value] = cookie_value(data)
            cookie[:expires] = Time.now + options[:expire_after] if options[:expire_after]
            cookie[:expires] = Time.now + options[:max_age] if options[:max_age]

            if @same_site.respond_to? :call
              cookie[:same_site] = @same_site.call(req, res)
            else
              cookie[:same_site] = @same_site
            end
            # Set-Cookie的值设为cookie
            set_cookie(req, res, cookie.merge!(options))
          end
        end
        public :commit_session

        def cookie_value(data)
          data
        end

        # Sets the cookie back to the client with session id. We skip the cookie
        # setting if the value didn't change (sid is the same) or expires was given.

        def set_cookie(request, res, cookie)
          if request.cookies[@key] != cookie[:value] || cookie[:expires]
            # 设置Set-Cookie头部，@key默认为rack.session, ghe初始化为_gh_manage
            # cookie的值为session id编码后加上hmac
            res.set_cookie_header =
              Utils.add_cookie_to_header(res.set_cookie_header, @key, cookie)
          end
        end

        # Allow subclasses to prepare_session for different Session classes

        def session_class
          SessionHash
        end

        # All thread safety and session retrieval procedures should occur here.
        # Should return [session_id, session].
        # If nil is provided as the session id, generation of a new valid id
        # should occur within.

        def find_session(env, sid)
          raise '#find_session not implemented.'
        end

        # All thread safety and session storage procedures should occur here.
        # Must return the session id if the session was saved successfully, or
        # false if the session could not be saved.

        def write_session(req, sid, session, options)
          raise '#write_session not implemented.'
        end

        # All thread safety and session destroy procedures should occur here.
        # Should return a new session id or nil if options[:drop]

        def delete_session(req, sid, options)
          raise '#delete_session not implemented'
        end
      end

      # Rack::Session::Cookie初始化的时候会调用这个父类进行初始化
      class PersistedSecure < Persisted
        class SecureSessionHash < SessionHash
          def [](key)
            if key == "session_id"
              load_for_read!
              case id
              when SessionId
                id.public_id
              else
                id
              end
            else
              super
            end
          end
        end

        def generate_sid(*)
          public_id = super

          SessionId.new(public_id)
        end

        def extract_session_id(*)
          public_id = super
          public_id && SessionId.new(public_id)
        end

        private

        def session_class
          SecureSessionHash
        end

        def cookie_value(data)
          data.cookie_value
        end
      end

      class ID < Persisted
        def self.inherited(klass)
          k = klass.ancestors.find { |kl| kl.respond_to?(:superclass) && kl.superclass == ID }
          unless k.instance_variable_defined?(:"@_rack_warned")
            warn "#{klass} is inheriting from #{ID}.  Inheriting from #{ID} is deprecated, please inherit from #{Persisted} instead" if $VERBOSE
            k.instance_variable_set(:"@_rack_warned", true)
          end
          super
        end

        # All thread safety and session retrieval procedures should occur here.
        # Should return [session_id, session].
        # If nil is provided as the session id, generation of a new valid id
        # should occur within.

        def find_session(req, sid)
          get_session req.env, sid
        end

        # All thread safety and session storage procedures should occur here.
        # Must return the session id if the session was saved successfully, or
        # false if the session could not be saved.

        def write_session(req, sid, session, options)
          set_session req.env, sid, session, options
        end

        # All thread safety and session destroy procedures should occur here.
        # Should return a new session id or nil if options[:drop]
        # 如果drop设置了，应该返回一个新的session id或者空
        def delete_session(req, sid, options)
          destroy_session req.env, sid, options
        end
      end
    end
  end
end
