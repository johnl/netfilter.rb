$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'test/unit'
require 'netfilter'

module Netfilter
  class NetfilterTest < Test::Unit::TestCase
    def test_filter
      assert filter = FilterTable.new
      assert_equal "filter", filter.name
      assert filter.input
      assert filter.forward
      assert filter.output
    end

    def test_simple_rules
      assert filter = FilterTable.new
      assert_equal 0, filter.rules.size
      assert filter.input.accept
      assert_equal 1, filter.rules.size
      assert filter.input.accept
      assert_equal 2, filter.rules.size
    end

    def test_combinated_rules
      assert filter = FilterTable.new
      assert filter.input.accept
      assert_equal 1, filter.rules.size
      assert filter.input.accept :src => [1,2]
      assert_equal 3, filter.rules.size
      assert filter.input.accept :src => [1,2], :dst => [3,4,5]
      assert_equal 9, filter.rules.size
      assert filter.input.accept :src => [1,2], :dst => [3,4,5], :proto => 'tcp'
      assert_equal 15, filter.rules.size
    end
  end
end
