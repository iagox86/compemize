$LOAD_PATH << File.dirname(__FILE__) # A hack to make this work on 1.8/1.9

require 'benchmark'
require 'openssl'

require 'LocalTestModule'
require 'RemoteTestModule'
require 'Unzipher'

TEST_COUNT = 256 # 256 is a reasonable value for quick tests

if(ARGV[0] == 'remote')
  # Attempt a remote check
  puts("Starting remote test (this requires RemoteTestServer.rb to be running on localhost:20222)")
  begin
    mod = RemoteTestModule.new

    time = Benchmark.measure do
      puts Unzipher.decrypt(mod, 'Cookie: SESSION_ID="', '"', true)
    end

    puts("Time: #{time}")

  rescue Errno::ECONNREFUSED => e
    puts(e.class)
    puts("Couldn't connect to remote server: #{e}")
  end
end

#srand(123456)

passes = 0
failures = 0

puts("*** [RC4] Testing 16-digit hex strings...")
1.upto(200) do
  mod = LocalTestModule.new("rc4", "abcdef0123456789", 16)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS: #{mod.data} == #{data}")
  else
    failures += 1
    puts("FAIL: #{mod.data} != #{data}")
  end
end

puts("*** [RC4] Testing 32-digit hex strings...")
1.upto(200) do
  mod = LocalTestModule.new("rc4", "abcdef0123456789", 32)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS: #{mod.data} == #{data}")
  else
    failures += 1
    puts("FAIL: #{mod.data} != #{data}")
  end
end

puts("*** [RC4] Testing 25-byte base64 strings (128-bits, encoded)")
1.upto(200) do
  mod = LocalTestModule.new("rc4", "+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS: #{mod.data} == #{data}")
  else
    failures += 1
    puts("FAIL: #{mod.data} != #{data}")
  end
end

puts("*** [DES-CBC] Testing 16-digit hex strings...")
1.upto(200) do
  mod = LocalTestModule.new("des-cbc", "abcdef0123456789", 16)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS: #{mod.data} == #{data}")
  else
    failures += 1
    puts("FAIL: #{mod.data} != #{data}")
  end
end

puts("*** [AES-256-CBC] Testing 16-digit hex strings...")
1.upto(200) do
  mod = LocalTestModule.new("aes-256-cbc", "abcdef0123456789", 16)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS: #{mod.data} == #{data}")
  else
    failures += 1
    puts("FAIL: #{mod.data} != #{data}")
  end
end

puts("Passes: #{passes}")
puts("Failures: #{failures}")
puts("Accuracy: #{passes.to_f / (passes.to_f + failures.to_f)}")

