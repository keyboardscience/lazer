module Lazer

  class ParserException < StandardError
  end

  module Parser
    class << self
      attr_accessor :parser, :uri

      def digest(uri)
        @uri = uri
        if /ubuntu/.match(uri)
          @parser = Lazer::Parser::USN.new(self.feed)
        else
          raise ParserException.new("Unknown feed!")
        end
        return @parser.digested
      end

      def feed
        open(@uri) do |rss|
          return RSS::Parser.parse(rss)
        end
      end
    end

    class USN
      attr_accessor :digested
      def initialize(feed)
        @digested = []
        feed.items.each do |item|
          @digested.push(parse(item))
        end
      end

      def parse(item)
        parsed = Nokogiri::HTML(item.description)
        usn_effected = {}

        usn_effected = usn_effected.merge(
        {
          usn: /usn-[0-9]+-[0-9]{1,3}/i.match(item.title)[0],
          date:  Date.parse(parsed.css('p em').children.first.text),
          cve: parsed.css('p').css('a').select { |d| /CVE.*$/.match(d.text) }.map { |c| c.text }.uniq 
        } )

        usn_effected_releases = parsed.css('ul')
                                      .css('li')
                                      .children
                                      .map { |c| c.text }
                                      .select { |v| /ubuntu/i.match(v) }

        usn_effected_releases.each.with_index do |e, i|
          usn_effected = usn_effected.merge(
              { 
                "#{e.to_s}": {
                  package: parsed.css("dl")
                                 .css("dd:nth-of-type(#{i+1})")
                                 .css("a:nth-of-type(1)")
                                 .first.text, 
                  rev: parsed.css("dl")
                           .css("dd:nth-of-type(#{i+1})")
                           .css("a:nth-of-type(1)")
                           .last.text 
                } 
              } )
        end
        return usn_effected
      end
    end
  end

end
