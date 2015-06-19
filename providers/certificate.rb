include Chef::AwsEc2::Credentials

def whyrun_supported?
  true
end

use_inline_resources

def load_current_resource
  @current_resource = Chef::Resource::AwsIamCertificate.new @new_resource.name
  @current_resource.client = Chef::AwsEc2::get_iam_client aws_credentials, aws_region
  @current_resource.certificate = Chef::AwsEc2.get_certificate @current_resource.name, @current_resource.client
  unless @current_resource.certificate.nil?
    @current_resource.path(@current_resource.certificate.server_certificate_metadata.path)
    @current_resource.certificate_body(@current_resource.certificate.certificate_body)
    @current_resource.certificate_chain(@current_resource.certificate.certificate_chain)
  end
  @current_resource.after_created
end

action :create do
  converge_by "Creating certificate '#{@new_resource.name}'" do
    create_certificate
    load_current_resource
  end unless @current_resource.exists?
  fail "Cannot change path #{@new_resource.path} -> #{@current_resource.path}" unless @current_resource.path == @new_resource.path
  fail "Cannot change certificate body: #{@current_resource.certificate_body_o.inspect} -> #{@new_resource.certificate_body_o.inspect}" unless @current_resource.certificate_body_o == @new_resource.certificate_body_o
  fail "Cannot change certificate chain" unless @current_resource.certificate_chain_o == @new_resource.certificate_chain_o
end

action :recreate do
  converge_by "Recreating certificate '#{@new_resource.name}' because it exists" do
    @current_resource.certificate.delete
    create_certificate
  end if @current_resource.exists?
end

action :delete do
  converge_by "Deleting certificate '#{@new_resource.name}'" do
    @current_resource.certificate.delete
  end if @current_resource.exists?
end

private

def create_certificate
  opts = {
      server_certificate_name: @new_resource.name,
      private_key: @new_resource.private_key,
      certificate_body: @new_resource.certificate_body
    }
    opts[:path] = @new_resource.path unless @new_resource.path.nil?
    fail 'Invalid chain' unless validate_chain @new_resource.certificate_body_o, @new_resource.certificate_chain_o
    opts[:certificate_chain] = serialize @new_resource.certificate_chain_o unless @new_resource.certificate_chain_o.nil?
    puts "Chain: #{opts[:certificate_chain]}"
    @current_resource.client.upload_server_certificate opts
end

private

def validate_chain base, chain
  return false if base.nil?
  return true if chain.nil? or chain.empty?
  t = chain.clone
  c = base
  until t.empty?
    return false unless c.issuer == t.first.subject
    c = t.slice! 0
  end
  true
end

def serialize certs
  return nil if certs.nil?
  certs.join("\n")
end
