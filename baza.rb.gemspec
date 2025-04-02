# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require 'English'
require_relative 'lib/baza-rb/version'

Gem::Specification.new do |s|
  s.required_rubygems_version = Gem::Requirement.new('>= 0') if s.respond_to? :required_rubygems_version=
  s.required_ruby_version = '>=3.0'
  s.name = 'baza.rb'
  s.version = BazaRb::VERSION
  s.license = 'MIT'
  s.summary = 'Zerocracy API Ruby Client'
  s.description =
    'It is a Ruby client for Zerocracy API, allowing you to check your jobs ' \
    'statuses, upload and download binaries, lock/unlock them, manage durables, ' \
    'and do everything else that is possible to do via the HTTP API.'
  s.authors = ['Yegor Bugayenko']
  s.email = 'yegor256@gmail.com'
  s.homepage = 'https://github.com/zerocracy/baza.rb'
  s.files = `git ls-files`.split($RS)
  s.rdoc_options = ['--charset=UTF-8']
  s.extra_rdoc_files = ['README.md', 'LICENSE.txt']
  s.add_dependency 'backtrace', '>0'
  s.add_dependency 'elapsed', '>0'
  s.add_dependency 'faraday', '>0'
  s.add_dependency 'faraday-http-cache', '>0'
  s.add_dependency 'faraday-multipart', '>0'
  s.add_dependency 'faraday-retry', '>0'
  s.add_dependency 'iri', '>0'
  s.add_dependency 'loog', '>0'
  s.add_dependency 'retries', '~>0'
  s.add_dependency 'tago', '~>0'
  s.add_dependency 'typhoeus', '~>1.3'
  s.metadata['rubygems_mfa_required'] = 'true'
end
