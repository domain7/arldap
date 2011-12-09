# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "arldap/version"

Gem::Specification.new do |s|
  s.name        = "arldap"
  s.version     = Arldap::VERSION
  s.authors     = ["Jody Alkema", "Shane Davies"]
  s.email       = ["jody@alkema.ca", "shane@domain7.com"]
  s.homepage    = ""
  s.summary     = %q{Active Record LDAP}
  s.description = %q{Provide an LDAP search interface to an ActiveRecord model in a Rails 3 project}

  s.rubyforge_project = "arldap"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # s.add_development_dependency "rspec"
  s.add_runtime_dependency "ruby-ldapserver"
end
