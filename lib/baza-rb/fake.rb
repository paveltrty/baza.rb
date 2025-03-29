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
  def push(_name, _data, _meta)
    42
  end

  # Pull factbase from the server.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Bytes] Binary data pulled
  def pull(_id)
    Factbase.new.export
  end

  # The job with this ID is finished already?
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Boolean] TRUE if the job is already finished
  def finished?(_id)
    true
  end

  # Read and return the stdout of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The stdout, as a text
  def stdout(_id)
    'Fake stdout output'
  end

  # Read and return the exit code of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [Integer] The exit code
  def exit_code(_id)
    0
  end

  # Read and return the verification verdict of the job.
  #
  # @param [Integer] id The ID of the job on the server
  # @return [String] The verdict
  def verified(_id)
    'fake-verdict'
  end

  # Lock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def lock(name, owner)
    # nothing
  end

  # Unlock the name.
  #
  # @param [String] name The name of the job on the server
  # @param [String] owner The owner of the lock (any string)
  def unlock(name, owner)
    # nothing
  end

  # Get the ID of the job by the name.
  #
  # @param [String] name The name of the job on the server
  # @return [Integer] The ID of the job on the server
  def recent(_name)
    42
  end

  # Check whether the name of the job exists on the server.
  #
  # @param [String] name The name of the job on the server
  # @return [Boolean] TRUE if such name exists
  def name_exists?(_name)
    true
  end

  # Place a single durable.
  #
  # @param [String] jname The name of the job on the server
  # @param [String] file The file name
  def durable_place(jname, file)
    # nothing
  end

  # Save a single durable from local file to server.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_save(id, file)
    # nothing
  end

  # Load a single durable from server to local file.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] file The file to upload
  def durable_load(id, file)
    # nothing
  end

  # Lock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_lock(id, owner)
    # nothing
  end

  # Unlock a single durable.
  #
  # @param [Integer] id The ID of the durable
  # @param [String] owner The owner of the lock
  def durable_unlock(id, owner)
    # nothing
  end

  # Transfer some funds to another user.
  #
  # @param [String] recipient GitHub name (e.g. "yegor256") of the recipient
  # @param [Float] amount The amount in Z/USDT (not zents!)
  # @param [String] summary The description of the payment
  def transfer(_recipient, _amount, _summary, *)
    42
  end

  # Pop job from the server.
  #
  # @param [String] owner Who is acting (could be any text)
  # @param [String] zip The path to ZIP archive to take
  # @return [Boolean] TRUE if job taken, otherwise false
  def pop(_owner, _zip)
    true
  end

  # Submit a ZIP archive to finish a job.
  #
  # @param [Integer] id The ID of the job on the server
  # @param [String] zip The path to the ZIP file with the content of the archive
  def finish(id, zip)
    # nothing
  end

  # Enter a valve.
  #
  # @param [String] name Name of the job
  # @param [String] badge Unique badge of the valve
  # @param [String] why The reason
  # @param [nil|Integer] job The ID of the job
  # @return [String] The result just calculated or retrieved
  def enter(_name, _badge, _why, _job)
    yield
  end

  # Get CSRF token from the server.
  # @return [String] The token for this user
  def csrf
    'fake-csrf-token'
  end
end
