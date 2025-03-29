# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright (c) 2024-2025 Zerocracy
# SPDX-License-Identifier: MIT

require_relative '../lib/baza-rb/fake'

# Test fake object.
# Author:: Yegor Bugayenko (yegor256@gmail.com)
# Copyright:: Copyright (c) 2024 Yegor Bugayenko
# License:: MIT
class TestFake < Minitest::Test
  def test_pull
    baza = BazaRb::Fake.new
    bin = baza.pull(42)
    refute_nil(bin)
  end
end
