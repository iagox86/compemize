##
# RemoteTestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
##
#
require 'httparty'

class RemoteTestModule
  NAME = "RemoteTestModule(tm)"

  def initialize()
  end

  def encrypt(data)
    result = HTTParty.get("http://localhost:20222/encrypt/#{data.unpack("H*").pop}")

    return [result.parsed_response].pack("H*").length
  end

  def character_set()
    # Return the perfectly optimal string, as a demonstration
    return 'abcdefABCDEF0123456789zyxwstvup'.chars.to_a
  end
end

