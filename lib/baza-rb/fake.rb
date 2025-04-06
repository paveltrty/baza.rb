# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require 'factbase'
require_relative '../baza-rb'
require_relative 'version'

# Fake interface to the API of zerocracy.com for testing.
#
# This class implements the same public interface as BazaRb but doesn't
# make any network connections, instead returning predefined fake values.
#
# Author:: Yegor Bugayenko (yegor256@gmail.com)
# Copyright:: Copyright (c) 2024-2025 Yegor Bugayenko
# License:: MIT
class BazaRb::Fake
  # Push factbase to the server.
  #
  # @param [String] name The name of the job on the server
  # @param [Bytes] data The data to push to the server (binary)
  # @param [Array<String>] meta List of metas, possibly empty
  # @return [Integer] Job ID on the server
  def push(name, data, meta)
    assert_name(name)
    raise 'The data must be non-empty' if data.empty?
    raise 'The meta must be an array' unless meta.is_a?(Array)
    42
  end

  # Pull factbase from the server.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Bytes] Binary data pulled
  def pull(id)
    assert_id(id)
    Factbase.new.export
  end

  # The job with this ID is finished already?
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Boolean] TRUE if the job is already finished
  def finished?(id)
    assert_id(id)
    true
  end

  # Read and return the stdout of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The stdout, as a text
  def stdout(id)
    assert_id(id)
    'Fake stdout output'
  end

  # Read and return the exit code of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Integer] The exit code
  def exit_code(id)
    assert_id(id)
    0
  end

  # Read and return the verification verdict of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The verdict
  def verified(id)
    assert_id(id)
    'fake-verdict'
  end

  # Lock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def lock(name, owner)
    assert_name(name)
    assert_owner(owner)
  end

  # Unlock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def unlock(name, owner)
    assert_name(name)
    assert_owner(owner)
  end

  # Get the ID of the job by the name.
  #
  # @param [String] name The name of the job on the server
  # @return [Integer] The ID of the job on the server
  def recent(name)
    assert_name(name)
    42
  end

  # Check whether the name of the job exists on the server.
  #
  # @param [String] name The name of the job on the server
  # @return [Boolean] TRUE if such name exists
  def name_exists?(name)
    assert_name(name)
    true
  end

  # Place a single durable.
  #
  # @param [String] jname The name of the job on the server
  # @param [String] file The file name
  def durable_place(jname, file)
    assert_name(jname)
    assert_file(file)
  end

  # Save a single durable from local file to server.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_save(id, file)
    assert_id(id)
    assert_file(file)
  end

  # Load a single durable from server to local file.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_load(id, file)
    assert_id(id)
    assert_file(file)
  end

  # Lock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_lock(id, owner)
    assert_id(id)
    assert_owner(owner)
  end

  # Unlock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_unlock(id, owner)
    assert_id(id)
    assert_owner(owner)
  end

  # Transfer some funds to another user.
  #
  # @param [String] recipient GitHub name (e.g. "yegor256") of the recipient
  # @param [Float] amount The amount in Z/USDT (not zents!)
  # @param [String] summary The description of the payment
  # @param [Integer] job The ID of the job or NIL
  # @param [Integer] job The amount of points just rewarded
  # @return [Integer] Receipt ID
  def transfer(recipient, amount, summary, job: nil, points: nil)
    raise "The receipient #{recipient.inspect} is not valid" unless recipient.match?(/^[a-zA-Z0-9-]+$/)
    raise "The amount #{amount} must be a Float" unless amount.is_a?(Float)
    raise "The amount #{amount} must be positive" unless amount.positive?
    raise "The summary #{summary.inspect} is empty" if summary.empty?
    raise 'The job must go together with points' if !job.nil? && points.nil?
    42
  end

  # Pop job from the server.
  #
  # @param [String] owner Who is acting (could be any text)
  # @param [String] zip The path to ZIP archive to take
  # @return [Boolean] TRUE if job taken, otherwise false
  def pop(owner, zip)
    assert_owner(owner)
    FileUtils.mkdir_p(File.dirname(zip))
    FileUtils.touch(zip)
    true
  end

  # Submit a ZIP archive to finish a job.
  #
  # @param [Integer] id The ID of the job on the server
  # @param [String] zip The path to the ZIP file with the content of the archive
  def finish(id, zip)
    assert_id(id)
    assert_file(zip)
  end

  # Enter a valve.
  #
  # @param [String] name Name of the job
  # @param [String] badge Unique badge of the valve
  # @param [String] why The reason
  # @param [nil|Integer] job The ID of the job
  # @return [String] The result just calculated or retrieved
  def enter(name, badge, why, job)
    assert_name(name)
    raise "The badge '#{badge}' is not valid" unless badge.match?(/^[a-zA-Z0-9_-]+$/)
    raise 'The reason cannot be empty' if why.empty?
    assert_id(job) unless job.nil?
    yield
  end

  # Get CSRF token from the server.
  # @return [String] The token for this user
  def csrf
    'fake-csrf-token'
  end

  private

  def assert_name(name)
    raise "The name #{name.inspect} is not valid" unless name.match?(/^[a-z0-9-]+$/)
    raise "The name #{name.inspect} is too long" if name.length > 32
  end

  def assert_id(id)
    raise 'The ID must be an Integer' unless id.is_a?(Integer)
    raise 'The ID must be positive' unless id.positive?
  end

  def assert_owner(owner)
    raise "The owner #{owner.inspect} is not valid" unless owner.match?(/^[a-zA-Z0-9-]+$/)
    raise "The owner #{owner.inspect} is too long" if owner.length > 64
  end

  def assert_file(file)
    raise 'The file must exist' unless File.exist?(file)
    raise 'The file must be non-empty' unless File.size(file).positive?
  end
end
