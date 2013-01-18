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

1.upto(10000) do
  mod = LocalTestModule.new("rc4", "abcdef0123456789", 32)
  data = Unzipher.decrypt(mod, "Cookie: SESSION_ID=\"", '"')

  if(data == mod.data)
    passes += 1
    puts("PASS")
  else
    failures += 1
    puts("FAIL")
  end
end

puts("Passes: #{passes}")
puts("Failures: #{failures}")

#0.upto(TEST_COUNT) do |i|
#  data = "abcdefghijklmnop"
#  cipher = ciphers.shuffle[0]
#  print("> #{cipher} with a prefix of #{i/2} bytes... ")
#
#  mod = LocalTestModule.new(cipher, data, nil, false, i/2)
#  d = Unzipher.decrypt(mod, has_padding(cipher), false)
#  if(d == data)
#    passes += 1
#    puts "Passed!"
#  else
#    failures += 1
#    puts "Failed!"
#    puts(mod.to_s)
#    exit
#  end
#end
#
## Do a bunch of very short strings
#(0..TEST_COUNT).to_a.each do |i|
#  data = (0..rand(100)).map{rand(255).chr}.join
#  cipher = ciphers.shuffle[0]
#  print("> #{cipher} with random short data... ")
#  mod = LocalTestModule.new(cipher, data, nil, false)
#  d = Unzipher.decrypt(mod, has_padding(cipher), false)
#  if(d == data)
#    passes += 1
#    puts "Passed!"
#  else
#    failures += 1
#    puts "Failed!"
#    puts(mod.to_s)
#    exit
#  end
#end
#
## Try the different ciphers
#ciphers.each do |cipher|
#  (0..TEST_COUNT).to_a.shuffle[0, 8].each do |i|
#    print("> #{cipher} with random data (#{i} bytes)... ")
#
#    data = (0..i).map{(rand(0x7E - 0x20) + 0x20).chr}.join
#    mod = LocalTestModule.new(cipher, data)
#    d = Unzipher.decrypt(mod, has_padding(cipher), false)
#    if(d == data)
#      passes += 1
#      puts "Passed!"
#    else
#      failures += 1
#      puts "Failed!"
#      puts(mod.to_s)
#    end
#  end
#end
#
#puts("Ciphers tested: #{ciphers.join(", ")}")
#puts("Tests passed: #{passes}")
#puts("Tests failed: #{failures}")
#

