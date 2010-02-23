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
      Rule.should_receive(:new).with any_args
      rule = Rule.new
      rule.stub!(:rules).and_return([nil])
      @chain.instance_variable_set("@rules", [rule, rule])
      @chain.rules.size.should == 2
    end

    it "should flatten all rules on the chain" do
      Rule.should_receive(:new).with any_args
      rule = Rule.new
      rule.stub!(:rules).and_return([nil,nil])
      @chain.instance_variable_set("@rules", [rule, rule])
      @chain.rules.size.should == 4
    end
  end

  describe "accept" do
    it "should create a new rule with the action of ACCEPT" do
      Rule.should_receive(:new).with(hash_including(:action => "ACCEPT", :protocol => :tcp))
      @chain.accept :protocol => :tcp
    end

    it "should override any specified action" do
      Rule.should_receive(:new).with(hash_including(:action => "ACCEPT"))
      @chain.accept :action => :drop
    end
  end

  describe "drop" do
    it "should create a new rule with the action of DROP" do
      Rule.should_receive(:new).with(hash_including(:action => "DROP", :protocol => :tcp))
      @chain.drop :protocol => :tcp
    end

    it "should override any specified action" do
      Rule.should_receive(:new).with(hash_including(:action => "DROP"))
      @chain.drop :action => :accept
    end
  end

  describe "log" do
    it "should create a new rule with the action of LOG" do
      Rule.should_receive(:new).with(hash_including(:action => "LOG", :protocol => :tcp))
      @chain.log :protocol => :tcp
    end

    it "should override any specified action" do
      Rule.should_receive(:new).with(hash_including(:action => "LOG"))
      @chain.log :action => :drop
    end
  end

  describe "jump" do
    it "should create a new rule with a jump option to the given chain string" do
      Rule.should_receive(:new).with(hash_including(:jump => @chain.name, :protocol => :tcp))
      @chain.jump :chain => @chain.name, :protocol => :tcp
    end

    it "should accept a chain object as an argument" do
      Rule.should_receive(:new).with(hash_including(:jump => @chain.name, :protocol => :tcp))
      @chain.jump :chain => @chain, :protocol => :tcp
    end

    it "should replace the :chain option value with the current chain" do
      Rule.should_receive(:new).with(hash_including(:chain => @chain))
      @chain.jump :chain => "test_chain"
    end

    it "should override any specified jump option" do
      Rule.should_receive(:new).with(hash_including(:jump => @chain.name))
      @chain.jump :chain => @chain.name, :jump => 'override this'
    end
  end

  describe "reject" do
    it "should create a new rule with the option :reject_with" do
      Rule.should_receive(:new).with(hash_including(:reject_with => :tcp_reset, :protocol => :tcp))
      @chain.reject :with => :tcp_reset, :protocol => :tcp
    end

    it "should override any specified :reject_with option" do
      Rule.should_receive(:new).with(hash_including(:reject_with => :tcp_reset))
      @chain.reject :with => :tcp_reset, :reject_with => :override_this
    end
  end

  describe "to_nfarg" do
    it "should return a portion of netfilter cmdline to append to the chain name" do
      @chain.to_nfarg.should == "-A #{@chain.name}"
    end
  end

  it "should know when it is representing a built-in chain" do
    Chain.new(@table, "FORWARD").is_builtin?.should == true
  end

end
