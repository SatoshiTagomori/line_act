# frozen_string_literal: true

require_relative "line_act/version"
require 'cgi'
require 'ht_req'
require 'securerandom'
require 'action_controller'
require 'active_record'
require 'rails/railtie'
require 'active_support'

module LineAct
  class Error < StandardError; end
  
  @error = []
  
  def self.help
    puts <<'EOF'
##################このGemの使い方######################
環境変数に下記のものを設定しておくこと。
LINE_CLIENT_ID・・・Line DeveloperコンソールでログインAPIのクライアントIDを確認
LINE_REDIRECT_URL・・・Line Developerコンソールで設定したリダイレクト用のURL
LINE_SCOPE・・・Line Login APIに問い合わせる内容。
LINE_SECRET・・・Line Developerコンソールで設定したシークレットキー
他にもユーザーテーブル(LineUser)とアクセスログテーブル(AccessLog)を設定する
リダイレクト先のコントローラーで
LineAct.profile_action(@_request,self,LineUser,AccessLog)
というふうに定義する
#######################################################
EOF
  end
    
  def self.basic_test(req,controller,user,access_log)
    #環境変数の存在チェック
    ENV['LINE_CLIENT_ID'].nil? ? @error.push('環境変数LINE_CLIENT_IDが存在しません'):nil
    ENV['LINE_REDIRECT_URL'].nil? ? @error.push('環境変数LINE_REDIRECT_URLが存在しません'):nil
    ENV['LINE_SECRET'].nil? ? @error.push('環境変数LINE_SECRETが存在しません'):nil
    ENV['LINE_SCOPE'].nil? ? @error.push('環境変数LINE_SCOPEが存在しません'):nil
    #ログインページの問題確認
    @error.push('ログインページへのURLに問題がある可能性があります') unless HtReq.request({:url=>self.get_login_url(req)}).code == '302'
  end
  
  
  def self.get_errors(req)
    req.session[:line_act_errors]=''
    @error.each do |e|
      req.session[:line_act_errors]+e
    end
    @error=[]
    nil
  end
  
  
    
  def self.profile_action(req,controller,user,access_log)
    self.case_have_access_token(req,user,access_log)
    self.case_first_contact(req,user,access_log)
    if req.session[:line_act_access_token].nil?
      controller.redirect_to self.get_login_url(req) and return
    end
    #エラーの取得
    self.basic_test(req,controller,user,access_log)
    self.get_errors(req)
  end

  def self.case_first_contact(req,user,access_log)
    if self.get_first_access_token(req)
      if self.get_first_user_info(req)
        self.insert_user_info(req,user)
        self.set_access_log(req,user,access_log)
      end
    end
  end

  def self.case_have_access_token(req,user,access_log)
    if self.has_access_token(req)
      if self.access_token_check(req)
        self.set_access_log(req,user,access_log)
      else
        self.user_sign_out(req)
      end
    end
  end


  def self.user_sign_out(req)
    req.session.each do |k,v|
      req.session[k]=nil
    end
  end
  
  def self.access_token_check(req)
    HtReq.get_json_data({
      :url=>'https://api.line.me/oauth2/v2.1/verify',
      :method=>'GET',
      :params=>{
        :access_token=>req.session[:line_act_access_token]
      }
    })
  end
  
  def self.has_access_token(req)
    req.session[:line_act_access_token].present? 
  end
  
  def self.set_access_log(req,user,access_log)
     access_log.create(:line_user_id=>user.find_by(:line_id=>req.session[:line_act_sub]).id,:ip=>req.remote_ip) 
  end

  def self.insert_user_info(req,user)
      #ユーザーが既に存在しなければ
      if user.find_by(:line_id=>req.session[:sub]).blank?
        #最初のユーザーであれば
        if user.all.count == 0
          user.create(:line_id=>req.session[:line_act_sub],:display_name=>req.session[:line_act_name],:picture=>req.session[:line_act_picture],:admin=>true)
        else
          user.create(:line_id=>req.session[:line_act_sub],:display_name=>req.session[:line_act_name],:picture=>req.session[:line_act_picture])
        end
      else
        #アップデートする
        user.find_by(:line_id=>req.session[:line_act_sub]).update(:line_id=>req.session[:line_act_sub],:display_name=>req.session[:line_act_name],:picture=>req.session[:line_act_picture])
      end
  end



  def self.get_first_user_info(req)
      if res = self.get_user_info(req.session[:line_act_id_token])
          req.session[:line_act_name] = res["name"]
          req.session[:line_act_picture]=res["picture"]
          req.session[:line_act_sub]=res["sub"]
          return true
      end
      @error.push('id_tokenからユーザー情報を取得できませんでした')
      return false
  end
  
  def self.get_user_info(id_token)
    HtReq.get_json_data({
      :url=>'https://api.line.me/oauth2/v2.1/verify',
      :method=>'POST',
      :params=>{
        :id_token=>id_token,
        :client_id=>ENV['LINE_CLIENT_ID'],
      }
    })
  end
  
  
  def self.get_first_access_token(req)
     if req.session[:line_act_access_token].nil? && req.params[:state] && req.params[:code]
        #トークンのチェック
        if req.params[:state]==req.session[:line_act_state]
            if res = self.get_access_token(req.params[:code])
               req.session[:line_act_access_token]=res["access_token"] 
               req.session[:line_act_refresh_token]=res["refresh_token"]
               req.session[:line_act_id_token]=res["id_token"]
               return true
            else
              @error.push('トークンが一致しません。(state)')
              return false
            end
        end
     end
     return false
  end
  
  
  #トークンを取得する
  def self.get_access_token(code)
    HtReq.get_json_data({
      :url=>'https://api.line.me/oauth2/v2.1/token',
      :method=>'POST',
      :params=>{
        :grant_type=>'authorization_code',
        :code=>code,
        :redirect_uri=>ENV['LINE_REDIRECT_URL'],
        :client_id=>ENV['LINE_CLIENT_ID'],
        :client_secret=>ENV['LINE_SECRET']
      },
      :header=>{
        "Content-Type":"application/x-www-form-urlencoded"
      }
    })
  end
  
  #ログインURLとcsrf_tokenを取得する
  def self.get_login_url(req)
    req.session[:line_act_state] = SecureRandom.hex(10)
    HtReq.set_get_params_to_url('https://access.line.me/oauth2/v2.1/authorize',
      {
        :response_type=>'code',
        :client_id=>ENV['LINE_CLIENT_ID'],
        :redirect_uri=>ENV['LINE_REDIRECT_URL'],
        :state=>req.session[:line_act_state],
        :scope=>ENV['LINE_SCOPE']
      }).to_s
  end
  
end
