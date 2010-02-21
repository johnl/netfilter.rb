Spec::Matchers.define :have_chains_named do |expected_chain_names|
  match do |table|
    actual_chain_names = table.chains.collect { |c| c.name }.sort
    actual_chain_names.should == expected_chain_names.sort
  end
end
