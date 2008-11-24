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
      @chains << Chain.new(self, name)
      @chains.last
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
    def initialize(*args)
      super(args)
      @name = "filter"
      new_chain("input")
      new_chain("forward")
      new_chain("output")
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

    def with_scope(*args, &block)
      @scope = args.first
      self.instance_exec(&block)
    ensure
      @scope = nil
    end

    def scope
      @scope||{}
    end

    def accept(options = {})
      new_rule(options.update(:action => :accept))
    end

    def drop(options = {})
      new_rule(options.update(:action => :drop))
    end

    def log(options = {})
      new_rule(options.update(:action => :log))
    end

    # Create a new rule, merging in any scope and passing in this chain
    def new_rule(options = {})
      @rules << Rule.new(options.update(scope).update(:chain => self))
    end

    def rules
      if @rules.empty?
        []
      else
        all_rules = []
        @rules.each { |r| all_rules += [to_nfarg, r.rules].combinate }
        all_rules
      end
    end

    def to_nfarg
      "-A #{name}"
    end
  end

  class Rule
    attr_reader :options
    attr_reader :chain
    
    NFOPTS = {
      :src => '-s',
      :dst => '-d',
      :protocol => { :opt => '-p', :aliases => :p },
      :state => '-m state --state',
      :dport => '--dport',
      :sport => '--sport',
      :in => '-i',
      :out => '-o',
      :prefix => '--log-prefix',
      :action => { :opt => '-j', :upcase => true }
    }

    def initialize(options = {})
      @chain = options.delete(:chain)
      @options = options
    end

    def rules
      options.combinate.collect { |o| Rule.new(o).to_nfargs }
    end

    def to_nfargs
      s = []
      options.keys.each do |k|
        val = options[k]
        val = val.to_nfarg if val.respond_to?(:to_nfarg)
        s << render_nfarg(k,val)
      end
      s.join(" ")
    end

    private

    def render_nfarg(search_key, value)
      NFOPTS.keys.each do |k|
        if NFOPTS[k].is_a? Hash
          options = NFOPTS[k]
          keys = [k, options[:aliases]].flatten
        else
          keys = [k]
          options = { :opt => NFOPTS[k]}
        end
        
        if keys.include? search_key
          opt = options[:opt]
          value = value.to_s.upcase if options[:upcase]
          return "#{opt} #{value}"
        end
      end
    end
    nil
  end

  def filter
    @filter_table ||= FilterTable.new
  end
end

