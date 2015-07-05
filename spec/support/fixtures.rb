module FixtureHelpers
  def fixture_filename(fn)
    spec_path = File.expand_path('../../', __FILE__)
    File.join(spec_path, 'fixtures', fn)
  end
end

RSpec.configure do |config|
  config.include FixtureHelpers
end
