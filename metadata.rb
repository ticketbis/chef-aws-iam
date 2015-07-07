name 'aws-iam'
maintainer 'Alberto Tablado'
maintainer_email 'alberto.tablado@ticketbis.com'
license 'Apache v2.0'
source_url 'https://github.com/ticketbis/chef-aws-iam'
description 'Manage AWS IAM'
long_description IO.read(File.join(
  File.dirname(__FILE__), 'README.md'
  )
)
version '0.1.0'

depends 'aws-base'
