module Netfilter
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
      new_rule(options.update(:action => "ACCEPT"))
    end

    def drop(options = {})
      new_rule(options.update(:action => "DROP"))
    end

    def log(options = {})
      new_rule(options.update(:action => "LOG"))
    end

    def jump(options = {})
      chain_name = options.delete(:chain)
      chain_name = chain_name.name if chain_name.is_a? Chain
      new_rule(options.update(:jump => chain_name))
    end

    def policy=(new_policy = nil)
      @policy = new_policy.to_s.upcase
    end

    def policy
      @policy || "ACCEPT"
    end

    def reject(options = {})
      reject_with = options.delete(:with)
      new_rule(options.update(:reject_with => reject_with))
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

    def to_nfheader
      if is_builtin?
        ":#{name} #{policy} [0:0]"
      else
        ":#{name} - [0:0]"
      end
    end

    def is_builtin?
      /^[A-Z]+$/ === name.to_s
    end
  end
end
