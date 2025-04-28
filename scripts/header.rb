#!/usr/bin/env ruby
# frozen_string_literal: true

files = `find src test -type f | grep -v mock_fiattoken | sort`
expected_header = `cat scripts/header.txt`
expected_header_length = expected_header.chomp.split("\n").length
puts "Checking that every file in src has the correct header...\n\n"

files.chomp.split("\n").each do |file|
  header = `cat #{file} | head -n #{expected_header_length}`
  if header == expected_header
    puts "✅ #{file}"
  else
    puts "❌ #{file}"
    `cat scripts/header.txt > #{file}.tmp`
    `tail -n +#{expected_header_length + 1} #{file} >> #{file}.tmp`
    `mv #{file}.tmp #{file}`
    puts "   Fixed header in #{file}"
  end
end
