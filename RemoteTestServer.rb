$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

##
# RemoteTestServer
# Created: January 17, 2013
# By: Ron Bowes
#
##

require 'openssl'
require 'sinatra'
require 'zlib'

set :port, 20222

# Note: Don't actually generate keys like this!
@@key = (1..32).map{rand(255).chr}.join
@@iv  = (1..32).map{rand(255).chr}.join
TEXT = <<EOF
HTTP/1.1 200 OK
Date: Thu, 17 Jan 2013 20:21:09 GMT
Server: Apache
X-Powered-By: PHP/5.3.15-pl0-gentoo
Connection: close
Cookie: SESSION_ID="d23d4b7245da1d9692438934082d0d33ed07dc6b40c7843ade5cfc1f79537200623a53b2f558302522348518ec8bfc05a3aa0805764e68f43470572e742d0dc16b7dc216bd975687720b76e42aa0f3bb197b59e7c285bbe77f8e8ab76fc91e899382ac2d0a3b0598ae4ab10d88446a61d99496c8cd3850660bf3c68e6f85f60b
Content-Type: text/html

EOF

MODE = "rc4"

get(/\/encrypt\/([a-fA-F0-9]*)$/) do |extra|
  c = OpenSSL::Cipher::Cipher.new(MODE)
  c.encrypt
  c.key = @@key

  extra = [extra].pack("H*")
  text = TEXT + extra
  deflated_text = (Zlib::Deflate.deflate(text))

  encrypted = c.update(deflated_text) + c.final

  puts("--------------------------------------------------------------------------------")
  puts("Text:")
  puts(text)
  puts("Length:            #{text.length}")
  puts("Compressed length: #{deflated_text.length}")
  puts("Encrypted length:  #{encrypted.length}")
  puts("--------------------------------------------------------------------------------")

  return encrypted.unpack("H*")
end

