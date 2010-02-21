module Netfilter
  module Protocols
    require 'ipaddr'
    require 'set'

    class Protocol
      PROTOCOL = nil

      def protocol
        self.class.const_get(:PROTOCOL)
      end
    end

    class ProtocolWithPort < Protocol
      attr_reader :port
    
      def initialize(port)
        @port = port
      end

      def to_nfargs
        if port.is_a? Range
          "#{port.min}:#{port.max}"
        else
          port.to_s
        end
      end

      def to_nfcmdline(options = {})
        "-p #{protocol} #{options[:opt]} #{to_nfarg}"
      end
    end

    class ProtocolWithMultiport < ProtocolWithPort
      attr_reader :ports
    
      def initialize(newports)
        @ports = newports.find_all { |p| p.is_a? Fixnum }
      end

      def to_nfcmdline(options = {})
        "-p #{protocol} -m multiport #{options[:opt]}s #{to_nfarg}"
      end

      def to_nfarg
        ports.join(",")
      end

      def empty?
        ports.empty?
      end
    end

    class Udp < ProtocolWithPort
      PROTOCOL = 'udp'
    end

    class Tcp < ProtocolWithPort
      PROTOCOL = 'tcp'
    end
  
    class MultiportUdp < ProtocolWithMultiport
      PROTOCOL = 'udp'
    end

    class MultiportTcp < MultiportUdp
      PROTOCOL = 'tcp'
    end

    class Icmp
      def initialize(type)
        @type = type
      end

      def to_s
        "icmp.#{@type}"
      end

      def to_nfcmdline(options = {})
        "-p icmp --icmp-type #{@type}"
      end
    end

    def tcp(*ports)
      build_protocols(ports.flatten, Tcp, MultiportTcp)
    end

    def udp(*ports)
      build_protocols(ports.flatten, Udp, MultiportUdp)
    end

    def icmp(types)
      [types].flatten.collect { |t| Icmp.new(t) }
    end

    def ip(*ips)
      ips.collect { |a| a.split(/ +/).collect { |b| IPAddr.new(b) } }.flatten
    end

    def build_protocols(ports, protocol, multiport_protocol)
      if ports.size > 1
        multiport = multiport_protocol.new(ports)
        ports -= multiport.ports
      end
      ports.collect! { |p| protocol.new(p) }
      ports << multiport unless multiport.nil? or multiport.empty?
      ports
    end
  end
end

