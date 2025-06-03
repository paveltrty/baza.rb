# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require 'factbase'
require 'loog'
require 'net/http'
require 'random-port'
require 'securerandom'
require 'socket'
require 'stringio'
require 'uri'
require 'wait_for'
require 'webrick'
require_relative 'test__helper'
require_relative '../lib/baza-rb'

# Test.
# Author:: Yegor Bugayenko (yegor256@gmail.com)
# Copyright:: Copyright (c) 2024-2025 Yegor Bugayenko
# License:: MIT
class TestBazaRb < Minitest::Test
  # The token to use for testing, in Zerocracy.com:
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
    assert(
      wait_for(200) do
        sleep(5)
        LIVE.finished?(id)
      end
    )
    refute_nil(LIVE.pull(id))
    refute_nil(LIVE.stdout(id))
    refute_nil(LIVE.exit_code(id))
    refute_nil(LIVE.verified(id))
    owner = 'baza.rb testing'
    refute_nil(LIVE.lock(n, owner))
    refute_nil(LIVE.unlock(n, owner))
  end

  def test_live_whoami
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    refute_nil(LIVE.whoami)
  end

  def test_live_balance
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    z = LIVE.balance
    refute_nil(z)
    assert(z.to_f)
  end

  def test_live_fee_payment
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    refute_nil(LIVE.fee('unknown', 0.007, 'just for fun', 777))
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
    id = fake_baza.transfer('jeff', 42.50, 'for fun')
    assert_equal(42, id)
  end

  def test_transfer_payment_with_job
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/csrf').to_return(body: 'token')
    stub_request(:post, 'https://example.org/account/transfer').to_return(
      status: 302, headers: { 'X-Zerocracy-ReceiptId' => '42' }
    )
    id = fake_baza.transfer('jeff', 42.50, 'for fun', job: 555)
    assert_equal(42, id)
  end

  def test_reads_whoami
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/whoami').to_return(status: 200, body: 'jeff')
    assert_equal('jeff', fake_baza.whoami)
  end

  def test_reads_balance
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/account/balance').to_return(status: 200, body: '42.33')
    assert_in_delta(42.33, fake_baza.balance)
  end

  def test_checks_whether_job_is_finished
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/finished/42').to_return(status: 200, body: 'yes')
    assert(fake_baza.finished?(42))
  end

  def test_reads_verification_verdict
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/jobs/42/verified.txt').to_return(status: 200, body: 'done')
    assert(fake_baza.verified(42))
  end

  def test_unlocks_job_by_name
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/unlock/foo?owner=x').to_return(status: 302)
    assert(fake_baza.unlock('foo', 'x'))
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
      assert_equal(42, fake_baza.durable_place('simple', file))
    end
  end

  def test_simple_push
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/push/simple').to_return(
      status: 200, body: '42'
    )
    assert_equal(
      42,
      fake_baza.push('simple', 'hello, world!', [])
    )
  end

  def test_simple_pop_with_no_job_found
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/pop?owner=me').to_return(status: 204)
    Tempfile.open do |zip|
      refute(fake_baza.pop('me', zip.path))
      refute_path_exists(zip.path)
    end
  end

  def test_simple_pop_with_ranges
    WebMock.disable_net_connect!
    owner = 'owner888'
    job = 4242
    stub_request(:get, 'https://example.org/pop')
      .with(query: { owner: })
      .to_return(
        status: 206,
        headers: { 'Content-Range' => 'bytes 0-0/*', 'X-Zerocracy-JobId' => job, 'Content-Length' => 0 },
        body: ''
      )
    bin = nil
    Tempfile.open do |zip|
      File.binwrite(zip.path, 'the archive to return (not a real ZIP for now)')
      bin = File.binread(zip.path)
      stub_request(:get, 'https://example.org/pop')
        .with(query: { job:, owner: })
        .with(headers: { 'Range' => 'bytes=0-' })
        .to_return(
          status: 206,
          headers: {
            'Content-Range' => "bytes 0-7/#{bin.size}",
            'X-Zerocracy-JobId' => job,
            'Content-Length' => 8
          },
          body: bin[0..7]
        )
      stub_request(:get, 'https://example.org/pop')
        .with(query: { job:, owner: })
        .with(headers: { 'Range' => 'bytes=8-' })
        .to_return(
          status: 206,
          headers: {
            'Content-Range' => "bytes 8-#{bin.size - 1}/#{bin.size}",
            'X-Zerocracy-JobId' => job,
            'Content-Length' => bin.size - 8
          },
          body: bin[8..]
        )
    end
    Tempfile.open do |zip|
      assert(fake_baza.pop(owner, zip.path))
      assert_path_exists(zip.path)
      assert_equal(bin, File.binread(zip.path))
    end
  end

  def test_simple_finish
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/finish?id=42').to_return(status: 200)
    Tempfile.open do |zip|
      fake_baza.finish(42, zip.path)
    end
  end

  def test_simple_recent_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/recent/simple.txt')
      .with(body: '', headers: { 'User-Agent' => /^baza.rb .*$/ })
      .to_return(status: 200, body: '42')
    assert_equal(
      42,
      fake_baza.recent('simple')
    )
  end

  def test_simple_exists_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/exists/simple').to_return(
      status: 200, body: 'yes'
    )
    assert(
      fake_baza.name_exists?('simple')
    )
  end

  def test_exit_code_check
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/exit/42.txt').to_return(
      status: 200, body: '0'
    )
    assert_predicate(
      fake_baza.exit_code(42), :zero?
    )
  end

  def test_stdout_read
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/stdout/42.txt').to_return(
      status: 200, body: 'hello!'
    )
    refute_empty(
      fake_baza.stdout(42)
    )
  end

  def test_simple_pull
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/pull/333.fb').to_return(
      status: 200, body: 'hello, world!'
    )
    assert(
      fake_baza.pull(333).start_with?('hello')
    )
  end

  def test_simple_lock_success
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/lock/name?owner=owner').to_return(status: 302)
    fake_baza.lock('name', 'owner')
  end

  def test_simple_lock_failure
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org/lock/name?owner=owner').to_return(status: 409)
    assert_raises(StandardError) do
      fake_baza.lock('name', 'owner')
    end
  end

  def test_push_with_server_failure
    WebMock.disable_net_connect!
    stub_request(:put, 'https://example.org/push/foo')
      .to_return(status: 503, body: 'oops', headers: { 'X-Zerocracy-Failure': 'the failure' })
      .to_raise('why second time?')
    e = assert_raises(StandardError) { fake_baza.push('foo', 'data', []) }
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
    fb = Factbase.new
    fb.insert.foo = 'test-' * 10_000
    req =
      with_http_server(200, 'yes') do |baza|
        baza.push('simple', fb.export, %w[meta1 meta2 meta3])
      end
    assert_equal('application/zip', req.content_type)
    assert_equal('gzip', req['content-encoding'])
    body = Zlib::GzipReader.zcat(StringIO.new(req.body))
    assert_equal(fb.export, body)
  end

  def test_push_compression_disabled
    WebMock.enable_net_connect!
    skip('We are offline') unless we_are_online
    fb = Factbase.new
    fb.insert.foo = 'test-' * 10_000
    req =
      with_http_server(200, 'yes', compress: false) do |baza|
        baza.push('simple', fb.export, %w[meta1 meta2 meta3])
      end
    assert_equal('application/octet-stream', req.content_type)
    assert_equal(fb.export, req.body)
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
      assert(t.join(1))
    end
  end

  def test_durable_save
    WebMock.disable_net_connect!
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'test.txt')
      File.write(file, 'test content')
      stub_request(:put, 'https://example.org:443/durables/42')
        .with(headers: { 'X-Zerocracy-Token' => '000' }, body: 'test content')
        .to_return(status: 200)
      fake_baza.durable_save(42, file)
    end
  end

  def test_durable_load
    WebMock.disable_net_connect!
    Dir.mktmpdir do |dir|
      file = File.join(dir, 'loaded.txt')
      stub_request(:get, 'https://example.org:443/durables/42')
        .with(headers: { 'X-Zerocracy-Token' => '000' })
        .to_return(status: 200, body: 'loaded content')
      fake_baza.durable_load(42, file)
      assert_equal('loaded content', File.read(file))
    end
  end

  def test_durable_lock
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/durables/42/lock?owner=test-owner')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 302)
    fake_baza.durable_lock(42, 'test-owner')
  end

  def test_durable_unlock
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/durables/42/unlock?owner=test-owner')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 302)
    fake_baza.durable_unlock(42, 'test-owner')
  end

  def test_fee
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/csrf')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 200, body: 'csrf-token')
    stub_request(:post, 'https://example.org:443/account/fee')
      .with(
        headers: { 'X-Zerocracy-Token' => '000' },
        body: {
          '_csrf' => 'csrf-token',
          'tab' => 'unknown',
          'amount' => '10.500000',
          'summary' => 'Test fee',
          'job' => '123'
        }
      )
      .to_return(status: 302, headers: { 'X-Zerocracy-ReceiptId' => '456' })
    receipt = fake_baza.fee('unknown', 10.5, 'Test fee', 123)
    assert_equal(456, receipt)
  end

  def test_enter
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/valves/result?badge=test-badge')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 200, body: 'cached result')
    result = fake_baza.enter('test-valve', 'test-badge', 'test reason', 123) { 'new result' }
    assert_equal('cached result', result)
  end

  def test_enter_not_cached
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/valves/result?badge=test-badge')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 204)
    stub_request(:get, 'https://example.org:443/csrf')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 200, body: 'csrf-token')
    stub_request(:post, 'https://example.org:443/valves/add?job=123')
      .with(
        headers: { 'X-Zerocracy-Token' => '000' },
        body: {
          '_csrf' => 'csrf-token',
          'name' => 'test-valve',
          'badge' => 'test-badge',
          'why' => 'test reason',
          'result' => 'new result'
        }
      )
      .to_return(status: 302)
    result = fake_baza.enter('test-valve', 'test-badge', 'test reason', 123) { 'new result' }
    assert_equal('new result', result)
  end

  def test_checked_with_500_error
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/test')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 500)
    error =
      assert_raises(BazaRb::ServerFailure) do
        fake_baza.send(
          :checked,
          Typhoeus.get('https://example.org:443/test', headers: { 'X-Zerocracy-Token' => '000' })
        )
      end
    assert_includes(error.message, 'Invalid response code #500')
    assert_includes(error.message, "most probably it's an internal error on the server")
  end

  def test_checked_with_503_error
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/test')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 503, headers: { 'X-Zerocracy-Failure' => 'Service unavailable' })
    error =
      assert_raises(BazaRb::ServerFailure) do
        fake_baza.send(
          :checked,
          Typhoeus.get('https://example.org:443/test', headers: { 'X-Zerocracy-Token' => '000' })
        )
      end
    assert_includes(error.message, 'Invalid response code #503')
    assert_includes(error.message, "most probably it's an internal error on the server")
    assert_includes(error.message, 'Service unavailable')
  end

  def test_checked_with_404_error
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/test')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 404)
    error =
      assert_raises(BazaRb::ServerFailure) do
        fake_baza.send(
          :checked,
          Typhoeus.get('https://example.org:443/test', headers: { 'X-Zerocracy-Token' => '000' })
        )
      end
    assert_includes(error.message, 'Invalid response code #404')
    assert_includes(error.message, 'most probably you are trying to reach a wrong server')
  end

  def test_checked_with_0_error
    WebMock.disable_net_connect!
    stub_request(:get, 'https://example.org:443/test')
      .with(headers: { 'X-Zerocracy-Token' => '000' })
      .to_return(status: 0)
    error =
      assert_raises(BazaRb::ServerFailure) do
        fake_baza.send(
          :checked,
          Typhoeus.get('https://example.org:443/test', headers: { 'X-Zerocracy-Token' => '000' })
        )
      end
    assert_includes(error.message, 'Invalid response code #0')
    assert_includes(error.message, 'most likely a connection failure')
  end

  def test_push_without_compression
    WebMock.disable_net_connect!
    baza = BazaRb.new('example.org', 443, '000', loog: Loog::NULL, compress: false)
    stub_request(:put, 'https://example.org:443/push/test')
      .with(
        headers: {
          'X-Zerocracy-Token' => '000',
          'Content-Type' => 'application/octet-stream',
          'Content-Length' => '4'
        },
        body: 'data'
      )
      .to_return(status: 200, body: '123')
    id = baza.push('test', 'data', [])
    assert_equal(123, id)
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
          len = req.header['content-length'].first.to_i
          if len == req.body.size
            socket.puts "HTTP/1.1 #{code} OK\r\nContent-Length: #{response.length}\r\n\r\n#{response}"
          else
            socket.puts "HTTP/1.1 400 Bad Request\r\n"
          end
          socket.close
        end
      yield BazaRb.new(host, port, '0000', **opts)
      assert(t.join(1))
    end
    req
  end

  def fake_baza
    BazaRb.new('example.org', 443, '000', loog: Loog::NULL)
  end

  def fake_name
    "fake#{SecureRandom.hex(8)}"
  end

  def we_are_online
    $we_are_online ||= !ARGV.include?('--offline') && uri_is_alive('https://www.zerocracy.com')
  end
  # rubocop:enable Style/GlobalVars

  # Checks whether this URI is alive (HTTP status is 200).
  def uri_is_alive(uri)
    Timeout.timeout(4) do
      require 'net/http'
      WebMock.enable_net_connect!
      Net::HTTP.get_response(URI(uri)).is_a?(Net::HTTPSuccess)
    rescue Timeout::Error, Timeout::ExitException, Socket::ResolutionError, Errno::EHOSTUNREACH, Errno::EINVAL
      puts "Ping failed to #{uri}"
      false
    end
  end
end
