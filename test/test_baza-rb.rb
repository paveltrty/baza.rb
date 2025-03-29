# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require 'factbase'
require 'loog'
require 'minitest/autorun'
require 'net/ping'
require 'random-port'
require 'securerandom'
require 'socket'
require 'stringio'
require 'wait_for'
require 'webmock/minitest'
require 'webrick'
require_relative '../lib/baza-rb'

# Test.
# Author:: Yegor Bugayenko (yegor256@gmail.com)
# Copyright:: Copyright (c) 2024 Yegor Bugayenko
# License:: MIT
class TestBazaRb < Minitest::Test
  # The token to use for testing:
  TOKEN = '00000000-0000-0000-0000-000000000000'

  # The host of the production platform:
  HOST = 'api.zerocracy.com'

  # The HTTPS port to use:
  PORT = 443

  # Live agent:
  LIVE = BazaRb.new(HOST, PORT, TOKEN, loog: Loog::VERBOSE)

  def test_live_push
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    fb = Factbase.new
    fb.insert.foo = 'test-' * 10_000
    fb.insert
    n = fake_name
    assert_predicate(LIVE.push(n, fb.export, []), :positive?)
    assert(LIVE.name_exists?(n))
    assert_predicate(LIVE.recent(n), :positive?)
    id = LIVE.recent(n)
    wait_for(60) { LIVE.finished?(id) }
    refute_nil(LIVE.pull(id))
    refute_nil(LIVE.stdout(id))
    refute_nil(LIVE.exit_code(id))
    refute_nil(LIVE.verified(id))
    owner = 'baza.rb testing'
    refute_nil(LIVE.lock(n, owner))
    refute_nil(LIVE.unlock(n, owner))
  end

  def test_live_push_no_compression
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    fb = Factbase.new
    fb.insert.foo = 'test-' * 10_000
    fb.insert
    baza = BazaRb.new(HOST, PORT, TOKEN, compress: false)
    assert_predicate(baza.push(fake_name, fb.export, []), :positive?)
  end

  def test_live_durable_lock_unlock
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    Dir.mktmpdir do |dir|
      file = File.join(dir, "#{fake_name}.bin")
      File.binwrite(file, 'hello')
      id = LIVE.durable_place(fake_name, file)
      owner = fake_name
      LIVE.durable_lock(id, owner)
      LIVE.durable_load(id, file)
      LIVE.durable_save(id, file)
      LIVE.durable_unlock(id, owner)
    end
  end

  def test_live_enter_valve
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    r = 'something'
    n = fake_name
    badge = fake_name
    assert_equal(r, LIVE.enter(n, badge, 'no reason', nil) { r })
    assert_equal(r, LIVE.enter(n, badge, 'no reason', nil) { nil })
  end

  def test_get_csrf_token
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    assert_operator(LIVE.csrf.length, :>, 10)
  end

  def test_transfer_payment
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/csrf').to_return(body: 'token')
    stub_request(:post, 'https://example.org/account/transfer').to_return(
      status: 302, headers: { 'X-Zerocracy-ReceiptId' => '42' }
    )
    id = BazaRb.new('example.org', 443, '000').transfer('jeff', 42.50, 'for fun')
    assert_equal(42, id)
  end

  def test_transfer_payment_with_job
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/csrf').to_return(body: 'token')
    stub_request(:post, 'https://example.org/account/transfer').to_return(
      status: 302, headers: { 'X-Zerocracy-ReceiptId' => '42' }
    )
    id = BazaRb.new('example.org', 443, '000').transfer('jeff', 42.50, 'for fun', job: 555)
    assert_equal(42, id)
  end

  def test_durable_place
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/csrf').to_return(body: 'token')
    stub_request(:post, 'https://example.org/durables/place').to_return(
      status: 302, headers: { 'X-Zerocracy-DurableId' => '42' }
    )
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'test.bin')
      File.binwrite(file, 'hello')
      assert_equal(42, BazaRb.new('example.org', 443, '000').durable_place('simple', file))
    end
  end

  def test_simple_push
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/push/simple').to_return(
      status: 200, body: '42'
    )
    assert_equal(
      42,
      BazaRb.new('example.org', 443, '000').push('simple', 'hello, world!', [])
    )
  end

  def test_simple_pop
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/pop?owner=me').to_return(status: 204)
    Tempfile.open do |zip|
      refute(BazaRb.new('example.org', 443, '000').pop('me', zip.path))
      refute_path_exists(zip.path)
    end
  end

  def test_simple_finish
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/finish?id=42').to_return(status: 200)
    Tempfile.open do |zip|
      BazaRb.new('example.org', 443, '000').finish(42, zip.path)
    end
  end

  def test_simple_recent_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/recent/simple.txt')
      .with(body: '', headers: { 'User-Agent' => /^baza.rb .*$/ })
      .to_return(status: 200, body: '42')
    assert_equal(
      42,
      BazaRb.new('example.org', 443, '000').recent('simple')
    )
  end

  def test_simple_exists_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/exists/simple').to_return(
      status: 200, body: 'yes'
    )
    assert(
      BazaRb.new('example.org', 443, '000').name_exists?('simple')
    )
  end

  def test_exit_code_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/exit/42.txt').to_return(
      status: 200, body: '0'
    )
    assert_predicate(
      BazaRb.new('example.org', 443, '000').exit_code(42), :zero?
    )
  end

  def test_stdout_read
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/stdout/42.txt').to_return(
      status: 200, body: 'hello!'
    )
    refute_empty(
      BazaRb.new('example.org', 443, '000').stdout(42)
    )
  end

  def test_simple_pull
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/pull/333.fb').to_return(
      status: 200, body: 'hello, world!'
    )
    assert(
      BazaRb.new('example.org', 443, '000').pull(333).start_with?('hello')
    )
  end

  def test_simple_lock_success
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/lock/name?owner=owner').to_return(status: 302)
    BazaRb.new('example.org', 443, '000').lock('name', 'owner')
  end

  def test_simple_lock_failure
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/lock/name?owner=owner').to_return(status: 409)
    assert_raises(StandardError) do
      BazaRb.new('example.org', 443, '000').lock('name', 'owner')
    end
  end

  def test_push_with_server_failure
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/push/foo')
      .to_return(status: 503, body: 'oops', headers: { 'X-Zerocracy-Failure': 'the failure' })
      .to_raise('why second time?')
    e = assert_raises(StandardError) { BazaRb.new('example.org', 443, '000').push('foo', 'data', []) }
    [
      'Invalid response code #503',
      '"the failure"'
    ].each { |t| assert_includes(e.message, t, "Can't find '#{t}' in #{e.message.inspect}") }
  end

  def test_real_http
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req =
      with_http_server(200, 'yes') do |baza|
        baza.name_exists?('simple')
      end
    assert_equal("baza.rb #{BazaRb::VERSION}", req['user-agent'])
  end

  def test_push_with_meta
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req =
      with_http_server(200, 'yes') do |baza|
        baza.push('simple', 'hello, world!', ['boom!', 'хей!'])
      end
    assert_equal('Ym9vbSE= 0YXQtdC5IQ==', req['x-zerocracy-meta'])
  end

  def test_push_with_big_meta
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req =
      with_http_server(200, 'yes') do |baza|
        baza.push(
          'simple',
          'hello, world!',
          [
            'pages_url:https://zerocracy.github.io/zerocracy.html',
            'others:https://zerocracy.github.io/zerocracy.html',
            'duration:59595'
          ]
        )
      end
    assert(req['x-zerocracy-meta'])
  end

  def test_push_compressed_content
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req =
      with_http_server(200, 'yes') do |baza|
        baza.push('simple', 'hello, world!', %w[meta1 meta2 meta3])
      end
    assert_equal('application/zip', req.content_type)
    assert_equal('gzip', req['content-encoding'])
    body = Zlib::GzipReader.zcat(StringIO.new(req.body))
    assert_equal('hello, world!', body)
  end

  def test_push_compression_disabled
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req =
      with_http_server(200, 'yes', compress: false) do |baza|
        baza.push('simple', 'hello, world!', %w[meta1 meta2 meta3])
      end
    assert_equal('application/octet-stream', req.content_type)
    assert_equal('hello, world!', req.body)
  end

  def test_with_very_short_timeout
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    host = '127.0.0.1'
    RandomPort::Pool::SINGLETON.acquire do |port|
      server = TCPServer.new(host, port)
      t =
        Thread.new do
          socket = server.accept
          req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
          req.parse(socket)
          req.body
          sleep 0.1
          socket.puts "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
          socket.close
        end
      assert_includes(
        assert_raises(StandardError) do
          BazaRb.new(host, port, '0000', ssl: false, timeout: 0.01).push('x', 'y', [])
        end.message, 'timed out in'
      )
      t.join
    end
  end

  private

  def with_http_server(code, response, opts = {})
    opts = { ssl: false, timeout: 1 }.merge(opts)
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    host = '127.0.0.1'
    RandomPort::Pool::SINGLETON.acquire do |port|
      server = TCPServer.new(host, port)
      t =
        Thread.new do
          socket = server.accept
          req.parse(socket)
          req.body
          socket.puts "HTTP/1.1 #{code} OK\r\nContent-Length: #{response.length}\r\n\r\n#{response}"
          socket.close
        end
      yield BazaRb.new(host, port, '0000', **opts)
      t.join
    end
    req
  end

  def fake_name
    "fake#{SecureRandom.hex(8)}"
  end

  def we_are_online
    @we_are_online ||= Net::Ping::External.new('8.8.8.8').ping?
  end
end
