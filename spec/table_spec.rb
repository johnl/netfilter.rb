require 'spec/helpers'
require File.join(File.dirname(__FILE__), '../lib/netfilter/table')
require File.join(File.dirname(__FILE__), '../lib/netfilter/chain')
include Netfilter

shared_examples_for "all tables" do

  it "should create methods for each chain" do
    table = Table.new('test_table')
    table.new_chain('test_chain')
    table.test_chain.should be_a_kind_of Chain
  end
  
  describe "new_chain" do
    it "should a new chain that knows about the table" do
      table = Table.new('test_table')
      new_chain = table.new_chain('test_chain')
      new_chain.table.should == table
    end

    it "should return the new chain" do
      table = Table.new('test_table')
      new_chain = table.new_chain('test_chain')
      new_chain.should be_a_kind_of Chain
      new_chain.name.should == 'test_chain'
    end
  end

end

describe Table do
  it_should_behave_like "all tables"
end

describe FilterTable do
  it_should_behave_like "all tables"
  
  it "should be named 'filter'" do
    FilterTable.new.name.should == 'filter'
  end

  it "should have chains named INPUT, FORWARD and OUTPUT" do
    FilterTable.new.should have_chains_named %w{ INPUT FORWARD OUTPUT }
  end  
end

