actions :create, :delete

default_action :create

attribute :name, kind_of: String, name_attribute: true
attribute :path, kind_of: String, default: '/'
attribute :private_key, kind_of: String, required: true
attribute :certificate_body, kind_of: String, required: true
attribute :certificate_chain, kind_of: [String, Array]
attribute :region, kind_of: String, required: true
attribute :access_key_id, kind_of: String, required: true
attribute :secret_access_key, kind_of: String, required: true

attr_accessor :client, :certificate, :certificate_chain_o, :certificate_body_o

require 'openssl'

class OpenSSL::X509::Certificate
  def inspect
    "{issuer: #{issuer}, serial: #{serial}, subject: #{subject}}"
  end
  def eql? other
    return false if other.nil?
    serial == other.serial and issuer == other.issuer and subject == other.subject
  end
  alias == eql?
end

def after_created
  begin 
    self.certificate_body_o = OpenSSL::X509::Certificate.new certificate_body unless @certificate_body.nil?
  rescue
    fail 'Invalid certificate body'
  end
  begin
    if certificate_chain.instance_of? String
      certificate_chain(certificate_chain.each_line.inject([]) do |r, line|
        if /-+BEGIN CERTIFICATE-+/ =~ line then r << line
        else r.last() << line unless r.last().nil?
        end
        r
      end
      )
      # fail 'Do not concatenate certificates. Please, make an array' if 
      #   certificate_chain.each_line.inject(0) do |res, line| 
      #     res += 1 if /BEGIN CERTIFICATE/ =~ line
      #     res
      #   end > 1
      # self.certificate_chain_o = [ OpenSSL::X509::Certificate.new(certificate_chain) ]
    end
    if certificate_chain.respond_to? :map
      self.certificate_chain_o = certificate_chain.map do |c|
        if c.instance_of? String then OpenSSL::X509::Certificate.new c
        else fail 'Certificate chain must be an array of valid certificates'
        end
      end
    else
      fail 'Unknown format for certificate chain'
    end 
    self.certificate_chain_o = reorder_chain certificate_body_o, certificate_chain_o
  rescue OpenSSL::X509::CertificateError
    fail 'Invalid certificate body in chain'
  end unless @certificate_chain.nil?
end

def exists?
  not certificate.nil?
end

def id
  certificate.id unless certificate.nil?
end

def certificate_chain_o=(val)
  fail 'Certificate chain must be an array of X509 certificates' unless val.instance_of? Array and val.all? {|c| c.instance_of? OpenSSL::X509::Certificate}
  @certificate_chain_o = val
  # @certificate_chain_o = reorder_chain val
end

private

def reorder_chain base, chain
  return nil if base.nil? or chain.nil?
  return [] if chain.empty?
  res = []
  t = chain.clone
  w = base
  o = 0
  if chain.respond_to? :find
    until w.nil?
      parent = t.find {|c| w.issuer == c.subject}
      break if parent.nil?
      t.delete parent
      res << parent
      w, o = parent, o + 1
      o += 1
    end
  end
  fail "Certificate chain incomplete, cannot find parent for #{w.inspect} in position #{o}. Matched: #{res.inspect}" unless t.empty? 
  res
end