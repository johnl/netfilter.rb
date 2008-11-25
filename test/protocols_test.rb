# To change this template, choose Tools | Templates
# and open the template in the editor.

$:.unshift File.join(File.dirname(__FILE__),'..','lib')

require 'test/unit'
require 'protocols'
include Protocols

module Protocols
  class ProtocolsTest < Test::Unit::TestCase
    def test_protocols
      assert_kind_of Tcp, tcp(80).first
      assert mp = tcp(80,443).first
      assert_kind_of MultiportTcp, mp
      assert ports = tcp(80,443,3000..3005)
      assert_kind_of MultiportTcp, ports.first
      assert_kind_of Tcp, ports.last
    end

  end
end
