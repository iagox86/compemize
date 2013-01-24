## Unzipher.rb
# Created: January 6, 2013
# By: Ron Bowes
#
# NAME A constant representing the name of the module, used for output.
#
# block_size() [optional] The blocksize of whatever cipher is being used, in
# bytes (eg, 16 for AES, 8 for DES, 1 for RC4, etc). Unzipher will automatically
# determine the blocksize if it's not given.
#
# encrypt(ciphertext) Attempt to decrypt the given data, and return
# true if there was no padding error and false if a padding error occured.
#
# character_set() [optional] If character_set() is defined, it is expected to
# return an array of characters in the order that they're likely to occur in
# the string. This allows modules to optimize themselves for, for example,
# filenames. The list doesn't need to be exhaustive; all other possible values
# are appended from 0 to 255.
#
# See LocalTestModule.rb and RemoteTestModule.rb for examples of how this can
# be implemented.
##

module Unzipher
  attr_accessor :verbose

  BAD_CHARACTER_RETRIES = 20
  BAD_RESULT_RETRIES = 10

  # Implement an ord() function that works in both Ruby 1.8 and Ruby 1.9
  def Unzipher.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  # Take a base_list, and add every charcter not already in the list
  def Unzipher.generate_set(base_list)
    mapping = []
    base_list.each do |i|
      mapping[ord(i)] = true
    end

    0.upto(255) do |i|
      if(!mapping[i])
        base_list << i.chr
      end
    end

    return base_list
  end

  def Unzipher.get_random_string(length)
    return (0..length).map{rand(255).chr}.join
  end

  # Figure out what the blocksize of the encryption algorithm is - either by
  # using one that the module provides, or by adding character slowly until the
  # size of the encrypted data changes
  def Unzipher.get_block_size(mod)
    # Check if the module has a block_size argument, and simply use it if it does
    if(mod.respond_to?(:block_size) && mod.block_size > 0)
      return mod.block_size
    end

    # Get the original size - with no encrypted data
    old_size = mod.encrypt("")

    # Try to add anywhere between 4 and 64 characters until it changes (every
    # algorithm I know of has either a 8 or 64-bit blocksize)
    1.step(64, 4) do |i|
      # Get the new size
      new_size = mod.encrypt(get_random_string(i))

      # When the size changes, return the difference
      if(new_size != old_size)
        return new_size - old_size
      end
    end
  end

  def Unzipher.do_character(mod, prefix, character_set)
    min_length = nil
    min = []

    random_set = (128..255).map do |i| i.chr end
    random_prefix  = (10..rand(100)).map{random_set[rand(random_set.size)]}.join
    random_postfix = (10..rand(100)).map{random_set[rand(random_set.size)]}.join

    character_set.each do |c|
      len = mod.encrypt(random_prefix + prefix + c + random_postfix)
      if(min_length.nil? || len == min_length)
         min << c
         min_length = len
      elsif(len < min_length)
        min_length = len
        min = [c]
      end
    end

    return min
  end

  # This is the main interface into Unzipher - it decrypts the data based on
  # the module given as the 'mod' parameter.
  #
  # has_padding is a little tricky - actual block ciphers (like ECB and CBC
  # mode) wind up with padding, but ciphers that are used as stream ciphers
  # (like OFB, PFB, RC4, and CTR) do not.  If you set it wrong, you'll either
  # get an error if you set has_padding = true on a stream cipher, or you'll
  # get a "\x01" byte at the end of your string if you set has_padding = false
  # when it is a block cipher.
  def Unzipher.decrypt(mod, prefix, postfix, verbose = false)
    # Make sure the compression is actually working as expected
    a = mod.encrypt(get_random_string(prefix.length - 1))
    b = mod.encrypt(prefix)

    #puts("a = #{a}, b = #{b}")

    if(b >= a)
      raise("The prefix doesn't encrypt to a shorter string!")
    end

    character_set = (mod.character_set + postfix).chars.sort.uniq

    result_failures = 0 # Goes up to BAD_RESULT_RETRIES
    result = ''
    begin
      possible_characters = character_set.clone

      character_failures = 0 # Goes up to BAD_CHARACTER_RETRIES
      loop do
        c = do_character(mod, prefix + result, character_set)
        possible_characters &= c

        if(possible_characters.length == 1)
          result += possible_characters[0]
          break
        else
          character_failures += 1
          if(character_failures > BAD_CHARACTER_RETRIES)
            break
          end
        end
      end

      # If we failed to narrow down the character
      if(possible_characters.length != 1)
        result_failures += 1 
        if(result_failures < BAD_RESULT_RETRIES)
          puts("False positive; resetting (attempt #{result_failures} of #{BAD_RESULT_RETRIES})...")
        end
        result = ""
      else
        if(result =~ /#{postfix}$/)
          break
        end
      end
    end while(result_failures <= BAD_RESULT_RETRIES)

    result = result.gsub(/#{postfix}$/, '')

    return result
  end
end
