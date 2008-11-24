module Protocols
  require 'ipaddr'

  class Udp
    def initialize(port)
      @port = port
    end

    def to_s
      "#{self.class.to_s.downcase}.#{@port}"
    end
  end

  class Tcp < Udp
  end

  class Icmp
    def initialize(code)
      @code = code
    end

    def to_s
      "icmp.#{@code}"
    end
  end

  def tcp(*ports)
    ports.collect { |port| Tcp.new(port) }
  end

  def udp(*ports)
    ports.collect { |port| Udp.new(port) }
  end

  def icmp(code)
    Icmp.new(code)
  end

  def ip(*ips)
    ips.collect { |a| a.split(/ +/).collect { |b| IPAddr.new(b) } }.flatten
  end
end


