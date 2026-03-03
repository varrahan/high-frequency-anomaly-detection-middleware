require_relative "../config/environment"
require "mocha/minitest"
require "rails/test_help"

module ActiveSupport
  class TestCase
    parallelize(workers: :number_of_processors)
  end
end