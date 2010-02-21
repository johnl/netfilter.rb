module Netfilter
  module Protocols
    require 'ipaddr'
    require 'set'

    class Protocol
      PROTOCOL = nil

      def protocol
        self.class.const_get(:PROTOCOL)
      end
      
      def ==(b)
        if b.respond_to? protocol
          protocol == b.protocol
        else
          super
        end
      end
    end

    class ProtocolWithPort < Protocol
      attr_reader :port
    
      def initialize(port)
        @port = port
      end

      def to_nfarg
        if port.is_a? Range
          "#{port.min}:#{port.max}"
        else
          port.to_s
        end
      end

      def to_nfcmdline(options = {})
        "-p #{protocol} #{options[:opt]} #{to_nfarg}"
      end
      
      def ==(b)
        port_matches = self.port == b.port if b.respond_to? :port
        port_matches and super
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

      def ==(b)
        if b.respond_to? :ports and b.ports.respond_to? :sort
          ports_match = self.ports.sort == b.ports.sort
        end
        ports_match and super
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
      attr_reader :icmp_type
      def initialize(icmp_type)
        @icmp_type = icmp_type
      end

      def to_s
        "icmp.#{icmp_type}"
      end

      def to_nfcmdline(options = {})
        "-p icmp --icmp-type #{icmp_type}"
      end
      
      def ==(b)
        if b.respond_to? :icmp_type
          type_matches = self.icmp_type == b.icmp_type
        end
        type_matches and super
      end
    end

    # Build Tcp or MultiportTcp objects for the given ports
    def tcp(*ports)
      build_protocols(ports.flatten, Tcp, MultiportTcp)
    end

    # Built Udp or MultiportUdp objects for the given ports
    def udp(*ports)
      build_protocols(ports.flatten, Udp, MultiportUdp)
    end

    # Build Icmp objects for the given icmp types
    def icmp(types)
      [types].flatten.collect { |t| Icmp.new(t) }
    end

    # Build IPAddr objects for the given IP addresses.  You can
    # provide IP addresses as multiple strings, or as space separated
    # strings.
    def ip(*ips)
      ips.collect { |a| a.split(/ +/).collect { |b| IPAddr.new(b) } }.flatten
    end

    # Return an array of appropriate objects representing the given
    # ports, removing any duplicates
    def build_protocols(ports, protocol, multiport_protocol)
      ports.uniq!
      single_ports = ports.select { |p| p.respond_to? :to_i }
      ranges = ports.select { |p| p.respond_to? :begin and p.respond_to? :end }
      result = []
      if single_ports.size == 1
        result << protocol.new(single_ports.first)
      elsif single_ports.size > 1
        result << multiport_protocol.new(single_ports)
      end
      result += ranges.collect { |p| protocol.new(p) }
    end
  end
end

