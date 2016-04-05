#!/usr/bin/env ruby

require 'open-uri'
require 'nokogiri'
require 'rss'

uri = "http://www.ubuntu.com/usn/rss.xml"
#uri = "http://seclists.org/rss/fulldisclosure.rss"

open(uri) do |rss|
  feed = RSS::Parser.parse(rss)
  parsed = Nokogiri::HTML(feed.items[0].description)

  if /ubuntu/.match(uri)
    usn_effected = {}

    usn_effected = usn_effected.merge({ 
                                          usn: /usn-[0-9]+-[0-9]{1,3}/i.match(feed.items[0].title),
                                          date:  Date.parse(parsed.css('p em').children.first.text),
                                          cve: parsed.css('p').css('a').select { |d| /CVE.*$/.match(d.text) }.map { |c| c.text }.uniq 
                                      })

    usn_effected_releases = parsed.css('ul').css('li').children.map { |c| c.text }.select { |v| /ubuntu/i.match(v) }

    usn_effected_releases.each.with_index do |e, i|
      usn_effected = usn_effected.merge({ "#{e.to_s}": { package: parsed.css("dl")
                                                                      .css("dd:nth-of-type(#{i+1})")
                                                                      .css("a:nth-of-type(1)")
                                                                      .first.text, 
                                                         rev: parsed.css("dl")
                                                                  .css("dd:nth-of-type(#{i+1})")
                                                                  .css("a:nth-of-type(1)")
                                                                  .last.text } })
    end

    p usn_effected
  end
end
