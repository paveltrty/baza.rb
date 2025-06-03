# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require 'base64'
require 'elapsed'
require 'fileutils'
require 'iri'
require 'loog'
require 'retries'
require 'stringio'
require 'tago'
require 'tempfile'
require 'typhoeus'
require 'zlib'
require_relative 'baza-rb/version'

# Ruby client for the Zerocracy API.
#
# This class provides a complete interface to interact with the Zerocracy
# platform API. Create an instance with your authentication token and use
# its methods to manage jobs, transfer funds, handle durables, and more.
#
# @example Basic usage
#   baza = BazaRb.new('api.zerocracy.com', 443, 'your-token-here')
#   puts baza.whoami        # => "your-github-username"
#   puts baza.balance       # => 100.5
#
# Author:: Yegor Bugayenko (yegor256@gmail.com)
# Copyright:: Copyright (c) 2024-2025 Yegor Bugayenko
# License:: MIT
class BazaRb
  # When the server failed (503).
  class ServerFailure < StandardError; end

  # When request timeout.
  class TimedOut < StandardError; end

  # Unexpected response arrived from the server.
  class BadResponse < StandardError; end

  # Initialize a new Zerocracy API client.
  #
  # @param [String] host The API host name (e.g., 'api.zerocracy.com')
  # @param [Integer] port The TCP port to connect to (usually 443 for HTTPS)
  # @param [String] token Your Zerocracy API authentication token
  # @param [Boolean] ssl Whether to use SSL/HTTPS (default: true)
  # @param [Float] timeout Connection and request timeout in seconds (default: 30)
  # @param [Integer] retries Number of retries on connection failure (default: 3)
  # @param [Loog] loog The logging facility (default: Loog::NULL)
  # @param [Boolean] compress Whether to use GZIP compression for requests/responses (default: true)
  def initialize(host, port, token, ssl: true, timeout: 30, retries: 3, loog: Loog::NULL, compress: true)
    @host = host
    @port = port
    @ssl = ssl
    @token = token
    @timeout = timeout
    @loog = loog
    @retries = retries
    @compress = compress
  end

  # Get GitHub login name of the logged in user.
  #
  # @return [String] GitHub nickname of the authenticated user
  # @raise [ServerFailure] If authentication fails or server returns an error
  def whoami
    nick = nil
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('whoami').to_s,
              headers:
            )
          )
        end
      nick = ret.body
      throw :"I know that I am @#{nick}, at #{@host}"
    end
    nick
  end

  # Get current balance of the authenticated user.
  #
  # @return [Float] The balance in zents (Ƶ), where 1 Ƶ = 1 USDT
  # @raise [ServerFailure] If authentication fails or server returns an error
  def balance
    z = nil
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('account').append('balance').to_s,
              headers:
            )
          )
        end
      z = ret.body.to_f
      throw :"The balance is Ƶ#{z}, at #{@host}"
    end
    z
  end

  # Push factbase to the server to create a new job.
  #
  # @param [String] name The unique name of the job on the server
  # @param [String] data The binary data to push to the server (factbase content)
  # @param [Array<String>] meta List of metadata strings to attach to the job
  # @return [Integer] Job ID assigned by the server
  # @raise [ServerFailure] If the push operation fails
  def push(name, data, meta)
    raise 'The "name" of the job is nil' if name.nil?
    raise 'The "name" of the job may not be empty' if name.empty?
    raise 'The "data" of the job is nil' if data.nil?
    raise 'The "meta" of the job is nil' if meta.nil?
    id = 0
    hdrs = headers.merge(
      'Content-Type' => 'application/octet-stream',
      'Content-Length' => data.bytesize
    )
    unless meta.empty?
      hdrs = hdrs.merge('X-Zerocracy-Meta' => meta.map { |v| Base64.encode64(v).delete("\n") }.join(' '))
    end
    params = {
      connecttimeout: @timeout,
      timeout: @timeout,
      body: data,
      headers: hdrs
    }
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.put(
              home.append('push').append(name).to_s,
              @compress ? zipped(params) : params
            )
          )
        end
      id = ret.body.to_i
      throw :"Pushed #{data.bytesize} bytes to #{@host}, job ID is ##{id}"
    end
    id
  end

  # Pull factbase from the server for a specific job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] Binary data of the factbase (can be saved to file)
  # @raise [ServerFailure] If the job doesn't exist or pull fails
  def pull(id)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    data = ''
    elapsed(@loog) do
      Tempfile.open do |file|
        File.open(file, 'wb') do |f|
          request = Typhoeus::Request.new(
            home.append('pull').append("#{id}.fb").to_s,
            method: :get,
            headers: headers.merge(
              'Accept' => 'application/zip, application/factbase'
            ),
            accept_encoding: 'gzip',
            connecttimeout: @timeout,
            timeout: @timeout
          )
          request.on_body do |chunk|
            f.write(chunk)
          end
          with_retries(max_tries: @retries, rescue: TimedOut) do
            request.run
          end
          checked(request.response)
        end
        data = File.binread(file)
        throw :"Pulled #{data.bytesize} bytes of job ##{id} factbase at #{@host}"
      end
    end
    data
  end

  # Check if the job with this ID is finished already.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Boolean] TRUE if the job has completed execution, FALSE otherwise
  # @raise [ServerFailure] If the job doesn't exist
  def finished?(id)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    finished = false
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('finished').append(id).to_s,
              headers:
            )
          )
        end
      finished = ret.body == 'yes'
      throw :"The job ##{id} is #{finished ? '' : 'not yet '}finished at #{@host}"
    end
    finished
  end

  # Read and return the stdout of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The stdout, as a text
  def stdout(id)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    stdout = ''
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('stdout').append("#{id}.txt").to_s,
              headers:
            )
          )
        end
      stdout = ret.body
      throw :"The stdout of the job ##{id} has #{stdout.split("\n").count} lines"
    end
    stdout
  end

  # Read and return the exit code of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Integer] The exit code
  def exit_code(id)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    code = 0
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('exit').append("#{id}.txt").to_s,
              headers:
            )
          )
        end
      code = ret.body.to_i
      throw :"The exit code of the job ##{id} is #{code}"
    end
    code
  end

  # Read and return the verification verdict of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The verdict
  def verified(id)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    verdict = ''
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('jobs').append(id).append('verified.txt').to_s,
              headers:
            )
          )
        end
      verdict = ret.body
      throw :"The verdict of the job ##{id} is #{verdict.inspect}"
    end
    verdict
  end

  # Lock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def lock(name, owner)
    raise 'The "name" of the job is nil' if name.nil?
    raise 'The "name" of the job may not be empty' if name.empty?
    raise 'The "owner" of the lock is nil' if owner.nil?
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('lock').append(name).add(owner:).to_s,
              headers:
            ),
            [302, 409]
          )
        end
      throw :"Job name '#{name}' locked at #{@host}" if ret.code == 302
      raise "Failed to lock '#{name}' job at #{@host}, it's already locked"
    end
  end

  # Unlock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def unlock(name, owner)
    raise 'The "name" of the job is nil' if name.nil?
    raise 'The "name" of the job may not be empty' if name.empty?
    raise 'The "owner" of the lock is nil' if owner.nil?
    raise 'The "owner" of the lock may not be empty' if owner.empty?
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        checked(
          Typhoeus::Request.get(
            home.append('unlock').append(name).add(owner:).to_s,
            headers:
          ),
          302
        )
      end
      throw :"Job name '#{name}' unlocked at #{@host}"
    end
  end

  # Get the ID of the job by the name.
  #
  # @param [String] name The name of the job on the server
  # @return [Integer] The ID of the job on the server
  def recent(name)
    raise 'The "name" of the job is nil' if name.nil?
    raise 'The "name" of the job may not be empty' if name.empty?
    job = nil
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('recent').append("#{name}.txt").to_s,
              headers:
            )
          )
        end
      job = ret.body.to_i
      throw :"The recent \"#{name}\" job's ID is ##{job} at #{@host}"
    end
    job
  end

  # Check whether the name of the job exists on the server.
  #
  # @param [String] name The name of the job on the server
  # @return [Boolean] TRUE if such name exists
  def name_exists?(name)
    raise 'The "name" of the job is nil' if name.nil?
    raise 'The "name" of the job may not be empty' if name.empty?
    exists = false
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.get(
              home.append('exists').append(name).to_s,
              headers:
            )
          )
        end
      exists = ret.body == 'yes'
      throw :"The name \"#{name}\" #{exists ? 'exists' : "doesn't exist"} at #{@host}"
    end
    exists
  end

  # Place a single durable file on the server.
  #
  # @param [String] jname The name of the job on the server
  # @param [String] file The path to the file to upload
  # @return [Integer] The ID of the created durable
  # @raise [ServerFailure] If the upload fails
  def durable_place(jname, file)
    raise 'The "jname" of the durable is nil' if jname.nil?
    raise 'The "jname" of the durable may not be empty' if jname.empty?
    raise 'The "file" of the durable is nil' if file.nil?
    raise "The file '#{file}' is absent" unless File.exist?(file)
    id = nil
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.post(
              home.append('durables').append('place').to_s,
              body: {
                '_csrf' => csrf,
                'jname' => jname,
                'file' => File.basename(file),
                'zip' => File.open(file, 'rb')
              },
              headers:,
              connecttimeout: @timeout,
              timeout: @timeout
            ),
            302
          )
        end
      id = ret.headers['X-Zerocracy-DurableId'].to_i
      throw :"Durable ##{id} (#{file}) placed for job \"#{jname}\" at #{@host}"
    end
    id
  end

  # Save a single durable from local file to server.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_save(id, file)
    raise 'The ID of the durable is nil' if id.nil?
    raise 'The ID of the durable must be a positive integer' unless id.positive?
    raise 'The "file" of the durable is nil' if file.nil?
    raise "The file '#{file}' is absent" unless File.exist?(file)
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        checked(
          Typhoeus::Request.put(
            home.append('durables').append(id).to_s,
            body: File.binread(file),
            headers:,
            connecttimeout: @timeout,
            timeout: @timeout
          )
        )
      end
      throw :"Durable ##{id} saved #{File.size(file)} bytes to #{@host}"
    end
  end

  # Load a single durable from server to local file.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_load(id, file)
    raise 'The ID of the durable is nil' if id.nil?
    raise 'The ID of the durable must be a positive integer' unless id.positive?
    raise 'The "file" of the durable is nil' if file.nil?
    FileUtils.mkdir_p(File.dirname(file))
    elapsed(@loog) do
      File.open(file, 'wb') do |f|
        request = Typhoeus::Request.new(
          home.append('durables').append(id).to_s,
          method: :get,
          headers: headers.merge(
            'Accept' => 'application/octet-stream'
          ),
          connecttimeout: @timeout,
          timeout: @timeout
        )
        request.on_body do |chunk|
          f.write(chunk)
        end
        with_retries(max_tries: @retries, rescue: TimedOut) do
          request.run
        end
        checked(request.response)
      end
      throw :"Durable ##{id} loaded #{File.size(file)} bytes from #{@host}"
    end
  end

  # Lock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_lock(id, owner)
    raise 'The ID of the durable is nil' if id.nil?
    raise 'The ID of the durable must be a positive integer' unless id.positive?
    raise 'The "owner" of the lock is nil' if owner.nil?
    raise 'The "owner" of the lock may not be empty' if owner.empty?
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        checked(
          Typhoeus::Request.get(
            home.append('durables').append(id).append('lock').add(owner:).to_s,
            headers:
          ),
          302
        )
      end
      throw :"Durable ##{id} locked at #{@host}"
    end
  end

  # Unlock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_unlock(id, owner)
    raise 'The ID of the durable is nil' if id.nil?
    raise 'The ID of the durable must be a positive integer' unless id.positive?
    raise 'The "owner" of the lock is nil' if owner.nil?
    raise 'The "owner" of the lock may not be empty' if owner.empty?
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        checked(
          Typhoeus::Request.get(
            home.append('durables').append(id).append('unlock').add(owner:).to_s,
            headers:
          ),
          302
        )
      end
      throw :"Durable ##{id} unlocked at #{@host}"
    end
  end

  # Transfer funds to another user.
  #
  # @param [String] recipient GitHub username of the recipient (e.g. "yegor256")
  # @param [Float] amount The amount to transfer in Ƶ (zents)
  # @param [String] summary The description/reason for the payment
  # @param [Integer] job Optional job ID to associate with this transfer
  # @return [Integer] Receipt ID for the transaction
  # @raise [ServerFailure] If the transfer fails
  def transfer(recipient, amount, summary, job: nil)
    raise 'The "recipient" is nil' if recipient.nil?
    raise 'The "amount" is nil' if amount.nil?
    raise 'The "amount" must be Float' unless amount.is_a?(Float)
    raise 'The "summary" is nil' if summary.nil?
    id = nil
    body = {
      '_csrf' => csrf,
      'human' => recipient,
      'amount' => format('%0.6f', amount),
      'summary' => summary
    }
    body['job'] = job unless job.nil?
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.post(
              home.append('account').append('transfer').to_s,
              body:,
              headers:,
              connecttimeout: @timeout,
              timeout: @timeout
            ),
            302
          )
        end
      id = ret.headers['X-Zerocracy-ReceiptId'].to_i
      throw :"Transferred Ƶ#{format('%0.6f', amount)} to @#{recipient} at #{@host}"
    end
    id
  end

  # Pay a fee associated with a job.
  #
  # @param [String] tab The category/type of the fee (use "unknown" if not sure)
  # @param [Float] amount The fee amount in Ƶ (zents)
  # @param [String] summary The description/reason for the fee
  # @param [Integer] job The ID of the job this fee is for
  # @return [Integer] Receipt ID for the fee payment
  # @raise [ServerFailure] If the payment fails
  def fee(tab, amount, summary, job)
    raise 'The "tab" is nil' if tab.nil?
    raise 'The "amount" is nil' if amount.nil?
    raise 'The "amount" must be Float' unless amount.is_a?(Float)
    raise 'The "job" is nil' if job.nil?
    raise 'The "job" must be Integer' unless job.is_a?(Integer)
    raise 'The "summary" is nil' if summary.nil?
    id = nil
    body = {
      '_csrf' => csrf,
      'tab' => tab,
      'amount' => format('%0.6f', amount),
      'summary' => summary,
      'job' => job.to_s
    }
    elapsed(@loog) do
      ret =
        with_retries(max_tries: @retries, rescue: TimedOut) do
          checked(
            Typhoeus::Request.post(
              home.append('account').append('fee').to_s,
              body:,
              headers:,
              connecttimeout: @timeout,
              timeout: @timeout
            ),
            302
          )
        end
      id = ret.headers['X-Zerocracy-ReceiptId'].to_i
      throw :"Fee Ƶ#{format('%0.6f', amount)} paid at #{@host}"
    end
    id
  end

  # Pop the next available job from the server's queue.
  #
  # @param [String] owner Identifier of who is taking the job (any descriptive text)
  # @param [String] zip The local file path where the job's ZIP archive will be saved
  # @return [Boolean] TRUE if a job was successfully popped, FALSE if queue is empty
  # @raise [ServerFailure] If the pop operation fails
  def pop(owner, zip)
    raise 'The "zip" of the job is nil' if zip.nil?
    success = false
    FileUtils.rm_f(zip)
    job = nil
    elapsed(@loog) do
      File.open(zip, 'wb+') do |f|
        loop do
          uri = home.append('pop').add(owner:)
          uri = uri.add(job:) if job
          request = Typhoeus::Request.new(
            uri.to_s,
            method: :get,
            headers: headers.merge(
              'Accept' => 'application/octet-stream',
              'Range' => "bytes=#{f.size}-"
            ),
            connecttimeout: @timeout,
            timeout: @timeout
          )
          request.on_body do |chunk|
            f.write(chunk)
          end
          with_retries(max_tries: @retries, rescue: TimedOut) do
            request.run
          end
          ret = request.response
          checked(ret, [200, 204, 206])
          success = ret.code != 204
          break unless ret.code == 206
          job = ret.headers['X-Zerocracy-JobId']
          raise 'Job ID is not returned in X-Zerocracy-JobId' if job.nil?
          raise "Job ID returned in X-Zerocracy-JobId is not valid (#{job.inspect})" unless job.match?(/^[0-9]+$/)
          _, v = ret.headers['Content-Range'].split
          range, total = v.split('/')
          raise "Total size is not valid (#{total.inspect})" unless total.match?(/^\*|[0-9]+$/)
          b, e = range.split('-')
          raise "Range is not valid (#{range.inspect})" unless e.match?(/^[0-9]+$/)
          len = ret.headers['Content-Length'].to_i
          unless len.zero?
            raise "Range size (#{range.inspect}) is not equal to Content-Length" unless len - 1 == e.to_i - b.to_i
            raise "Range end (#{range.inspect}) is not equal to #{f.size}" if e.to_i != f.size - 1
          end
          break if e.to_i == total.to_i - 1
        end
      end
      unless success
        FileUtils.rm_f(zip)
        throw :"Nothing to pop at #{@host}"
      end
      throw :"Popped #{File.size(zip)} bytes in ZIP archive at #{@host}"
    end
    success
  end

  # Submit a ZIP archive to finish a previously popped job.
  #
  # @param [Integer] id The ID of the job to finish
  # @param [String] zip The path to the ZIP file containing job results
  # @raise [ServerFailure] If the submission fails
  def finish(id, zip)
    raise 'The ID of the job is nil' if id.nil?
    raise 'The ID of the job must be a positive integer' unless id.positive?
    raise 'The "zip" of the job is nil' if zip.nil?
    raise "The 'zip' file is absent: #{zip}" unless File.exist?(zip)
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        checked(
          Typhoeus::Request.put(
            home.append('finish').add(id:).to_s,
            connecttimeout: @timeout,
            timeout: @timeout,
            body: File.binread(zip),
            headers: headers.merge(
              'Content-Type' => 'application/octet-stream',
              'Content-Length' => File.size(zip)
            )
          )
        )
      end
      throw :"Pushed #{File.size(zip)} bytes to #{@host}, finished job ##{id}"
    end
  end

  # Enter a valve to cache or retrieve a computation result.
  #
  # Valves prevent duplicate computations by caching results. If a result
  # for the given badge already exists, it's returned. Otherwise, the block
  # is executed and its result is cached.
  #
  # @param [String] name Name of the job
  # @param [String] badge Unique identifier for this valve/computation
  # @param [String] why The reason/description for entering this valve
  # @param [nil|Integer] job Optional job ID to associate with this valve
  # @yield Block that computes the result if not cached
  # @return [String] The cached result or newly computed result from the block
  # @raise [ServerFailure] If the valve operation fails
  def enter(name, badge, why, job)
    elapsed(@loog, intro: "Entered valve #{badge} to #{name}") do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        ret = checked(
          Typhoeus::Request.get(
            home.append('valves').append('result').add(badge:).to_s,
            headers:
          ),
          [200, 204]
        )
        return ret.body if ret.code == 200
        r = yield
        uri = home.append('valves').append('add')
        uri = uri.add(job:) unless job.nil?
        checked(
          Typhoeus::Request.post(
            uri.to_s,
            body: {
              '_csrf' => csrf,
              'name' => name,
              'badge' => badge,
              'why' => why,
              'result' => r.to_s
            },
            headers:
          ),
          302
        )
        r
      end
    end
  end

  # Get CSRF token from the server for authenticated requests.
  #
  # The CSRF token is required for POST requests to prevent cross-site
  # request forgery attacks.
  #
  # @return [String] The CSRF token for the authenticated user
  # @raise [ServerFailure] If token retrieval fails
  def csrf
    token = nil
    elapsed(@loog) do
      with_retries(max_tries: @retries, rescue: TimedOut) do
        token = checked(
          Typhoeus::Request.get(
            home.append('csrf').to_s,
            headers:
          ),
          200
        ).body
      end
      throw :"CSRF token retrieved (#{token.length} chars)"
    end
    token
  end

  private

  def headers
    {
      'User-Agent' => "baza.rb #{BazaRb::VERSION}",
      'Connection' => 'close',
      'X-Zerocracy-Token' => @token
    }
  end

  def zipped(params)
    body = gzip(params.fetch(:body))
    headers = params
      .fetch(:headers)
      .merge(
        {
          'Content-Type' => 'application/zip',
          'Content-Encoding' => 'gzip',
          'Content-Length' => body.bytesize
        }
      )
    params.merge(body:, headers:)
  end

  def gzip(data)
    (+'').tap do |result|
      io = StringIO.new(result)
      gz = Zlib::GzipWriter.new(io)
      gz.write(data)
      gz.close
    end
  end

  def home
    Iri.new('')
      .host(@host)
      .port(@port)
      .scheme(@ssl ? 'https' : 'http')
  end

  # Check the HTTP response and return it.
  #
  # @param [Typhoeus::Response] ret The response
  # @param [Array<Integer>] allowed List of acceptable HTTP codes
  # @return [Typhoeus::Response] The same response
  def checked(ret, allowed = [200])
    allowed = [allowed] unless allowed.is_a?(Array)
    mtd = (ret.request.original_options[:method] || '???').upcase
    url = ret.effective_url
    if ret.return_code == :operation_timedout
      msg = "#{mtd} #{url} timed out in #{ret.total_time}s"
      @loog.error(msg)
      raise TimedOut, msg
    end
    log = "#{mtd} #{url} -> #{ret.code} (#{format('%0.2f', ret.total_time)}s)"
    if allowed.include?(ret.code)
      @loog.debug(log)
      return ret
    end
    @loog.debug("#{log}\n  #{(ret.headers || {}).map { |k, v| "#{k}: #{v}" }.join("\n  ")}")
    headers = ret.headers || {}
    msg = [
      "Invalid response code ##{ret.code} ",
      "at #{mtd} #{url}",
      headers['X-Zerocracy-Flash'] ? " (#{headers['X-Zerocracy-Flash'].inspect})" : ''
    ].join
    case ret.code
    when 500
      msg +=
        ", most probably it's an internal error on the server, " \
        'please report this to https://github.com/zerocracy/baza'
    when 503
      msg +=
        ", most probably it's an internal error on the server (#{headers['X-Zerocracy-Failure'].inspect}), " \
        'please report this to https://github.com/zerocracy/baza.rb'
    when 404
      msg +=
        ", most probably you are trying to reach a wrong server, which doesn't " \
        'have the URL that it is expected to have'
    when 0
      msg +=
        ', most likely a connection failure, timeout, or SSL error ' \
        "(r:#{ret.return_code}, m:#{ret.return_message})"
    end
    @loog.error(msg)
    raise ServerFailure, msg
  end
end
