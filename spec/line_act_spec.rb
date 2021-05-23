# frozen_string_literal: true
require 'ht_req'
require 'active_support'

RSpec.describe LineAct do
  it "バージョンの有無の確認" do
    expect(LineAct::VERSION).not_to be nil
  end

  it "必要な環境変数の存在確認" do
    #expect(false).to eq(true)
    expect(ENV['LINE_CLIENT_ID'].nil? \
    || ENV['LINE_REDIRECT_URL'].nil? \
    || ENV['LINE_SECRET'].nil? \
    || ENV['LINE_SCOPE'].nil?).to eq(false)
  end
  
  
end
