#!/usr/bin/env ruby
# -*- encoding: utf-8 -*-

# TODO
# - APNIC の出力をパーズする
# - 出力のフォーマットを決める
# - RIPE
# - ARIN

require 'csv'
require 'ipaddr'
require 'socket'

class RIRtable
  def initialize
    @tab = []
    CSV.foreach("ipv6-unicast-address-assignments.csv") { |row|
      next if row[0] == "Prefix"  # first line
      @tab << row.values_at(0, 1, 3)
    }
  end

  def lookup(addrstr)
    ip = IPAddr.new(addrstr)
    @tab.each { |a|
      prefix = IPAddr.new a[0]
      return a if prefix.include?(ip)
    }
    [ "::/0", "NOTALLOCATED", nil ]
  end
end

module Whois
  class Generic
    def query(str)
      sock = TCPSocket.open @host, 43
      sock.write "#{str}\r\n"
      result = sock.read
      sock.close
      result
    end
  end

  class APNIC < Generic
    def initialize
      @host = "whois.apnic.net" 
    end
  end

  class RIPE < Generic
    def initialize
      @host = "whois.ripe.net" 
    end
  end
end

class RSPL
  def initialize(text)
    @text = text
  end
end

def usage
  puts "usage: whoare <ipaddr>"
  exit
end

usage if ARGV.size == 0

ARGV.each { |host|
  a = Addrinfo.getaddrinfo(host, nil, :INET6)
  if a.size == 0
    puts "#{ipaddr} has no ipv6 address"
    next
  end

  ipaddr = a[0].ip_address
  a = RIRtable.new.lookup ipaddr
  if a[2] == "whois.apnic.net"
    whois = Whois::APNIC.new
    puts whois.query(ipaddr)
  elsif a[2] == "whois.ripe.net"
    puts Whois::RIPE.new.query(ipaddr)
  else
    puts "#{ipaddr} is allocated to #{a[1]}"
  end
}
