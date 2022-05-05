class hiera_aws_sm () {

# package { 'aws-sdk-secretsmanager':
#   ensure   => 'present',
#   provider => 'puppet_gem',
# }


# package { 'aws-sdk-core':
#   ensure   => 'present',
#   provider => 'puppetserver_gem',
# }

# package { 'aws-sdk-secretsmanager':
#   ensure   => 'present',
#   provider => 'puppetserver_gem',
# }

package { 'aws-sdk':
  ensure   => 'present',
  provider => 'puppetserver_gem',
}




}
