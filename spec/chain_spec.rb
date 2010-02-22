require File.join(File.dirname(__FILE__), '../lib/netfilter/chain')
require File.join(File.dirname(__FILE__), '../lib/netfilter/table')
require File.join(File.dirname(__FILE__), '../lib/netfilter/combinate')

include Netfilter

describe Chain do
  before :all do
    Rule = mock("Rule")
  end

  before :each do
    @table = Table.new('test_table')
    @chain = Chain.new(@table, "test_chain")
  end

  it "should be initialized with a table and a name" do
    @chain.should be_a_kind_of Chain
    @chain.table.should == @table
    @chain.name.should == 'test_chain'
  end
  
  it "should have an ACCEPT policy by default" do
    @chain.policy.should == "ACCEPT"
  end
  
  it "should take a string when setting the policy and ensure it is uppercase" do
    @chain.policy = "drop"
    @chain.policy.should == "DROP"    
  end
  
  describe "new_rule" do
    it "should instantiate a Rule object with chain set to itself" do
      Rule.should_receive(:new).with(hash_including(:chain => @chain))
      @chain.new_rule
    end
    
    it "should merge the scope hash into the options" do
      Rule.should_receive(:new).with(hash_including(:animal => :monkey))
      @chain.instance_variable_set("@scope", { :animal => :monkey })
      @chain.new_rule
    end
  end
  
  describe "rules" do
    it "should be an empty Array by default" do
      @chain.rules.should be_empty
    end
    
    it "should return all rules on the chain" do
      pending
      Rule.should_receive(:new).with any_args
      rule = Rule.new
      rule.stub!(:rules).and_return([])
      @chain.instance_variable_set("@rules", [rule, rule])
      @chain.rules.size.should == 2
    end
  end
end
