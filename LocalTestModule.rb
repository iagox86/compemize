## LocaltestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
#
##

require 'openssl'
require 'zlib'

class LocalTestModule
  attr_reader :ciphertext, :character_set, :data

  NAME = "LocalTestModule(tm)"

  def initialize(mode, character_set, length)
    # Generate random data
    @data = (1..length).map{character_set[rand(character_set.size)].chr}.join
    @mode = mode
    @character_set = character_set
    @key = (1..32).map{character_set[rand(character_set.size)].chr}.join

    #puts("Generated session key: #{@data}")
  end

  def encrypt(data)
text = <<EOF
HTTP/1.1 200 OK
Date: Thu, 17 Jan 2013 20:21:09 GMT
Server: Apache
X-Powered-By: PHP/5.3.15-pl0-gentoo
Connection: close
Cookie: SESSION_ID="#{@data}"
Content-Type: text/html

EOF

    #puts(text + data)
    text = Zlib::Deflate.deflate(text + data)


    c = OpenSSL::Cipher::Cipher.new(@mode)
    c.encrypt
    c.key = @key
    return (c.update(text) + c.final()).length
  end
end
