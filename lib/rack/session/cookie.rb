# frozen_string_literal: true

# 对于服务端来说，理解的是session,对于客户端来说看到的是cookie
# 所以需要把session编码为cookie,发送给客户端。
# 解码来自客户端的cookie,让服务端理解这是不是有效的session,是不是一个可持续的会话。

require 'openssl'
require 'zlib'
require_relative 'abstract/id'
require 'json'
require 'base64'
require 'delegate'

module Rack

  module Session

    # Rack::Session::Cookie provides simple cookie based session management.
    # By default, the session is a Ruby Hash stored as base64 encoded marshalled
    # data set to :key (default: rack.session).  The object that encodes the
    # session data is configurable and must respond to +encode+ and +decode+.
    # Both methods must take a string and return a string.
    #
    # Rack::Session::Cookie提供了一个简单的基于cookie的session管理。
    # 默认的，session是一个Ruby Hash,储存为base64编码的marshalled data,设置为:key(默认为rack.session)。
    # 编码session data的对象是可以配置的，对应为encode和decode。
    # 这两个方法传入一个字符串和返回一个字符串。
    
    # When the secret key is set, cookie data is checked for data integrity.
    # The old secret key is also accepted and allows graceful secret rotation.
    #
    # 当这个secret key设置了，cookie data用来检查数据的完整性。
    # 
    # Example:
    #
    #     use Rack::Session::Cookie, :key => 'rack.session',
    #                                :domain => 'foo.com',
    #                                :path => '/',
    #                                :expire_after => 2592000,
    #                                :secret => 'change_me',
    #                                :old_secret => 'also_change_me'
    #
    #     All parameters are optional.
    #
    # 上面的写法相当于(使用use来把这个instance放入stack中)
    # Rack::Session::Cookie.new(application, {
    #                                :key => 'rack.session',
    #                                :domain => 'foo.com',
    #                                :path => '/',
    #                                :expire_after => 2592000,
    #                                :secret => 'change_me',
    #                                :old_secret => 'also_change_me'  
    # })
    
    
    # Example of a cookie with no encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Rack::Session::Cookie::Identity.new
    #   })
    #
    # Example of a cookie with custom encoding:
    #
    #   Rack::Session::Cookie.new(application, {
    #     :coder => Class.new {
    #       def encode(str); str.reverse; end
    #       def decode(str); str.reverse; end
    #     }.new
    #   })
    #

    class Cookie < Abstract::PersistedSecure
      # Encode session cookies as Base64
      # base64 class
      # 下面定义了三种编解码的方式
      class Base64
        # 用base64编码一个字符串
        def encode(str)
          ::Base64.strict_encode64(str)
        end
  
        # 用base64解码字符串
        def decode(str)
          ::Base64.decode64(str)
        end

        # Encode session cookies as Marshaled Base64 data
        class Marshal < Base64
          # 先用Marshal dump字符串，再用base64编码
          def encode(str)
            super(::Marshal.dump(str))
          end

          # 先用base64解码，再用Marshal解码
          # marshal.load不要传入不信任的输入参数。
          def decode(str)
            return unless str
            ::Marshal.load(super(str)) rescue nil
          end
        end

        # N.B. Unlike other encoding methods, the contained objects must be a
        # valid JSON composite type, either a Hash or an Array.
        class JSON < Base64
          # 先用JSON dump字符串，再用base64编码
          def encode(obj)
            super(::JSON.dump(obj))
          end

          # 先用base64解码，再用JSON解码
          # JSON.parse比Marshal.load更安全？？？
          def decode(str)
            return unless str
            ::JSON.parse(super(str)) rescue nil
          end
        end

        class ZipJSON < Base64
          def encode(obj)
            super(Zlib::Deflate.deflate(::JSON.dump(obj)))
          end

          def decode(str)
            return unless str
            ::JSON.parse(Zlib::Inflate.inflate(super(str)))
          rescue
            nil
          end
        end
      end

      # Use no encoding for session cookies
      # 不设置编解码
      class Identity
        def encode(str); str; end
        def decode(str); str; end
      end

      attr_reader :coder

      # 初始化Rack::Session::Cookie
      def initialize(app, options = {})
        @secrets = options.values_at(:secret, :old_secret).compact
        @hmac = options.fetch(:hmac, "SHA1")

        # 检查设置的选项是否安全
        # 安全警告，没有提供secret选项给Rack::Session::Cookie
        # 这个暴露出一个安全威胁。强烈建议提供一个secret来阻止可能的构造的cookie
        warn <<-MSG unless secure?(options)
        SECURITY WARNING: No secret option provided to Rack::Session::Cookie.
        This poses a security threat. It is strongly recommended that you
        provide a secret to prevent exploits that may be possible from crafted
        cookies. This will not be supported in future versions of Rack, and
        future versions will even invalidate your existing user cookies.

        Called from: #{caller[0]}.
        MSG
        # 如果没有设置coder,就用Base64::Marshal.new
        # 默认的编解码方式是危险的？？？？
        @coder = options[:coder] ||= Base64::Marshal.new
        # 执行父类的initialize方法，即Abstract::PersistedSecure的initialize方法
        super(app, options.merge!(cookie_only: true))
      end

      private

      # 根据请求和session id找到session
      def find_session(req, sid)
        # unpacked 来自请求的cookie数据
        data = unpacked_cookie_data(req)
        data = persistent_session_id!(data)
        [data["session_id"], data]
      end

      # 根据请求提取session id
      def extract_session_id(request)
        unpacked_cookie_data(request)["session_id"]
      end

      # 根据请求unpack cookie数据
      # 将来自客户端的cookie数据解码成服务端可以理解的session数据
      def unpacked_cookie_data(request)
        request.fetch_header(RACK_SESSION_UNPACKED_COOKIE_DATA) do |k|
          session_data = request.cookies[@key]

          if @secrets.size > 0 && session_data
            # 得到session_data和hmac
            session_data, _, digest = session_data.rpartition('--')
            # 判断hmac是否匹配
            session_data = nil unless digest_match?(session_data, digest)
          end

          # 如果来自客户端的hmac对的上，就解码session_data
          request.set_header(k, coder.decode(session_data) || {})
        end
      end

      def persistent_session_id!(data, sid = nil)
        data ||= {}
        data["session_id"] ||= sid || generate_sid
        data
      end

      class SessionId < DelegateClass(Session::SessionId)
        attr_reader :cookie_value

        def initialize(session_id, cookie_value)
          super(session_id)
          # cookie_value是编码后的session id加上hmac
          @cookie_value = cookie_value
        end
      end

      # 写session
      def write_session(req, session_id, session, options)
        # 给session hash添加session_id字段
        session = session.merge("session_id" => session_id)
        # 编码session hash
        # 对服务端易于理解的session数据编码成cookie
        session_data = coder.encode(session)

        if @secrets.first
          # 通过session_data和secret生成hmac, 并把生成的hmac放到session_data中
          session_data << "--#{generate_hmac(session_data, @secrets.first)}"
        end
        # 上面的代码已经生成了发送给客户端的cookie

        # session data的大小是否超过4096
        if session_data.size > (4096 - @key.size)
          req.get_header(RACK_ERRORS).puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
          nil
        else
          # 根据session_id和编码的session_data得到SessionId instance
          SessionId.new(session_id, session_data)
        end
      end

      # 删除session
      def delete_session(req, session_id, options)
        # Nothing to do here, data is in the client
        generate_sid unless options[:drop]
      end

      # 判断来自客户端的hmac是否匹配
      def digest_match?(data, digest)
        return unless data && digest
        @secrets.any? do |secret|
          Rack::Utils.secure_compare(digest, generate_hmac(data, secret))
        end
      end

      # 生成hmac
      def generate_hmac(data, secret)
        OpenSSL::HMAC.hexdigest(@hmac, secret, data)
      end

      # 检查选项是否安全
      def secure?(options)
        # secrets的大小大于1或者（coder和let_coder_handle_secure_encodeing这两个选项设置了）
        @secrets.size >= 1 ||
        (options[:coder] && options[:let_coder_handle_secure_encoding])
      end

    end
  end
end
