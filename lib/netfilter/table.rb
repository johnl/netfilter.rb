module Netfilter
  class Table
    attr_reader :name
    attr_reader :chains

    def initialize(name)
      @name = name
      @chains = []
    end

    def new_chain(name)
      @chains.unshift(Chain.new(self, name))
      @chains.first
    end

    def method_missing(method, *args)
      if chain = @chains.find { |c| c.name.to_s.downcase == method.to_s.downcase }
        chain
      else
        super
      end
    end

    def rules
      all_rules = []
      @chains.each do |c|
        c.rules.each { |r| all_rules << [to_nfarg, r].join(' ') }
      end
      all_rules
    end

    def to_nfarg
      "-t #{name}"
    end

  end

  class FilterTable < Table
    def initialize(*args)
      super(args)
      @name = "filter"
      new_chain("INPUT")
      new_chain("FORWARD")
      new_chain("OUTPUT")
    end
  end
end
