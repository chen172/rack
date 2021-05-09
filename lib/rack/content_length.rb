# frozen_string_literal: true

module Rack

  # Sets the Content-Length header on responses that do not specify
  # a Content-Length or Transfer-Encoding header.  Note that this
  # does not fix responses that have an invalid Content-Length
  # header specified.
  # 为在响应还没有设置Content-Length或者Transfer-Encoding头部的设置Content-Length头部。
  class ContentLength
    include Rack::Utils

    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, body = @app.call(env)
      headers = HeaderHash[headers]

      # 没有设置Content-Length和Transfer-Encoding头部
      if !STATUS_WITH_NO_ENTITY_BODY.key?(status.to_i) &&
         !headers[CONTENT_LENGTH] &&
         !headers[TRANSFER_ENCODING]

        obody = body
        # 初始化长度
        body, length = [], 0
        # 得到返回的内容体的长度
        obody.each { |part| body << part; length += part.bytesize }

        body = BodyProxy.new(body) do
          obody.close if obody.respond_to?(:close)
        end

        headers[CONTENT_LENGTH] = length.to_s
      end

      [status, headers, body]
    end
  end
end
