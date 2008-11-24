module Netfilter

  require 'lib/combinate'

  class Table
    attr_reader :name
    attr_reader :chains

    def initialize(name)
      @name = name
      @chains = []
    end

    def new_chain(name)
      Chain.new(self, name)
    end

    def method_missing(method, *args)
      if chain = @chains.find { |c| c.name == method.to_s }
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
    def initialize
      @name = "filter"
      @chains = []
      @chains << new_chain("input")
      @chains << new_chain("forward")
      @chains << new_chain("output")
    end
  end

  class Chain
    attr_reader :name
    attr_reader :table

    def initialize(table, name)
      @table = table
      @name = name
      @rules = []
    end

    def accept(options = {})
      @rules << Rule.new(options.update(:chain => self, :action => :accept))
    end

    def drop(options = {})
      @rules << Rule.new(options.update(:chain => self, :action => :drop))
    end

    def log(options = {})
      @rules << Rule.new(options.update(:chain => self, :action => :log))
    end

    def rules
      if @rules.empty?
        []
      else
        all_rules = []
        @rules.each { |r| all_rules += [to_nfarg, r.to_nfargs].combinate }
        all_rules
      end
    end

    def to_nfarg
      "-A #{name}"
    end
  end

  class Rule
    attr_reader :options

    def initialize(options = {})
      @options = options
    end

    def to_nfargs
      options.combinate.collect { |o| "rule: #{o.keys.join(" ")}" }
    end

  end

  def filter
    @filter_table ||= FilterTable.new
  end
end

