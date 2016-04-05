module Lazer

  class AnalyzerException < StandardError
  end

  module Analyzer
    class << self
      INSTALLED_SOFTWARE_INGEST = JSON.parse(File.open('/users/kevin.phillips/installed_sw.json').read)
      OS_VERSIONS = ["Ubuntu 14.04 LTS"]

      attr_accessor :threats, :digests

      def is_threat
        threat_digests = @digests.select { |d| is_applicable(d) }
        threat_digests = threat_digests.map { |d| combine_w_installed_version d }
        return threat_digests
      end

      def combine_w_installed_version digest
        installed = {}
        OS_VERSIONS.each do |o|
          installed_version = find_installed_version digest[o.to_sym]
          installed[o.to_sym] = installed_version.first unless installed_version.nil?
        end
        return digest.merge({ installed: installed })
      end

      # pkg_spec looks like { :package => '', :rev => '' }
      def find_installed_version pkg_spec
        installed = INSTALLED_SOFTWARE_INGEST["installed_software"].select do |installed_spec|
          if installed_spec["package"] == pkg_spec[:package]
            if installed_spec["rev"] != pkg_spec[:rev]
              true
            end
          end
        end
        return installed
      end

      def is_installed? pkg_spec
        installed = find_installed_version pkg_spec
        return (installed.empty?) ? false : true
      end

      def is_applicable digest
        filtered = digest.select do |k,v|
          OS_VERSIONS.include? k.to_s
        end
        check = filtered.select do |k,v|
          is_installed? v
        end
        return (check.empty?) ? false : true
      end
    end
  end
end
