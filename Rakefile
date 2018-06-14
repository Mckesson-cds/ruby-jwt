require 'bundler/gem_tasks'

begin
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new(:test_exceptions) do |t|
    t.exclude_pattern = 'spec/**/*activemodel_spec.rb'
  end

  RSpec::Core::RakeTask.new(:test_activemodel) do |t|
    t.pattern = 'spec/**/*activemodel_spec.rb'
  end

  task test: %w[test_exceptions test_activemodel]
  task default: :test

rescue LoadError
  puts 'RSpec rake tasks not available. Please run "bundle install" to install missing dependencies.'
end

