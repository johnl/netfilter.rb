require File.join(File.dirname(__FILE__), '../lib/netfilter/protocols')
include Netfilter
include Protocols

describe Protocols do
  
  describe "tcp" do
    it "should return an array of one Tcp object when given one integer" do
      tcp(80).size.should == 1
      tcp(80).first.should be_a_kind_of Tcp
    end
    
    it "should return an array of one MultiportTcp object when given two integers" do
      tcp(80,443).size.should == 1
      tcp(80,443).first.should be_a_kind_of MultiportTcp
    end
    
    it "should return an array of one Tcp object when given a range" do
      tcp(6667..6669).size.should == 1
      tcp(6667..6669).first.should be_a_kind_of Tcp
    end
    
    it "should return an array of one Tcp object and one MultiportTcp object when given a range and two integers" do
      result = tcp(6667..6669, 80, 443)
      result.size.should == 2
      result.should include Tcp.new(6667..6669)
      result.should include MultiportTcp.new([80,443])
    end
    
    it "should merge all non-contiguous integer arguments into one MultiportTcp" do
      result = tcp(80, 443, 6667..6669, 81)
      result.size.should == 2
      result.should include Tcp.new(6667..6669)
      result.should include MultiportTcp.new([80,443,81])
    end
  end
end
