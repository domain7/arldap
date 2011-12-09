#!/usr/bin/env ruby
require "ruby-ldapserver-0.3/lib/ldap/server"

class ActiveRecordOperation < LDAP::Server::Operation
  attr_accessor :schema, :server, :attributes, :connection
  
  def initialize(connection, messageID, config, ar_class, logger)
    @config, @ar_class, @logger = config, ar_class, logger
    @logger.debug "Received connection request (#{messageID})."
    @connection = connection
    super(connection, messageID)
  end
 
  def simple_bind(version, dn, password)
    @logger.debug "config password"
    @logger.debug @config[:password]
    @logger.debug "config password class"
    @logger.debug @config[:password].class
    @logger.debug "passed password"
    @logger.debug password
    @logger.debug "passed password class"
    @logger.debug password.class
    
    @connection.opt[:authentic] = password == @config[:password]
    if @connection.opt[:authentic]
      @logger.info  "simple_bind authentic: #{@connection.opt[:authentic]}"
    else
      @logger.info  "simple_bind not authentic: #{@connection.opt[:authentic]}"
    end
  end
  
  def search(basedn, scope, deref, filter)
    if @connection.opt[:authentic]
      @logger.info "Valid credentials: #{@connection.opt[:authentic]}"
    else
      @logger.info "Invalid credentials"
      raise LDAP::ResultError::InvalidCredentials, "Invalid credentials: #{@connection.opt[:authentic]}"
    end

    # This is needed to force the ruby ldap server to return our parameters, 
    # even though the client didn't explicitly ask for them
    @attributes << "*"
    if basedn != @config[:basedn]
      @logger.info "Denying request with missmatched basedn (wanted \"#{@config[:basedn]}\", but got \"#{basedn}\")"
      raise LDAP::ResultError::UnwillingToPerform, "Bad base DN"
    end

    if scope == LDAP::Server::BaseObject
      @logger.info "Denying request for BaseObject: #{filter.inspect}"
      raise LDAP::ResultError::UnwillingToPerform, "BaseObject not implemented: #{filter}"
    end

    query_string = parse_filter(filter)
    
    @logger.debug "Running #{@ar_class.name}.ldap_search(\"#{query_string}\")"
    
    begin
      @records = @ar_class.ldap_search(query_string)
    rescue Exception => e
      @logger.error "ERROR running #{@ar_class.name}.ldap_search(#{query_string}): #{e}"
      # raise LDAP::ResultError::OperationsError, "Error encountered during processing: #{e}."
    end 

    @logger.info "Returning #{@records.size} records matching \"#{query_string}\"."
    
    @records.each do |record| 
      begin
        ret = record.to_ldap_entry
      rescue
        @logger.error "ERROR converting AR instance to ldap entry: #{$!}"
        raise LDAP::ResultError::OperationsError, "Error encountered during processing."
      end
      
      ret_basedn = "uid=#{ret["uid"]},#{@config[:basedn]}"
      @logger.debug "Sending #{ret_basedn} - #{ret.inspect}" 
      send_SearchResultEntry(ret_basedn, ret)
    end
  end
  
  def parse_filter(filter)
    # format of mozilla and OS X address book searches are always this: 
    # [:or, [:substrings, "mail",      nil, nil, "XXX", nil], 
    #       [:substrings, "cn",        nil, nil, "XXX", nil], 
    #       [:substrings, "givenName", nil, nil, "XXX", nil], 
    #       [:substrings, "sn",        nil, nil, "XXX", nil]]
    # (with the order of the subgroups maybe turned around)
    ##
    # [:or, [:substrings, "givenname", nil, "j", nil], 
    # [:substrings, "sn", nil, "j", nil], 
    # [:substrings, "mail", nil, "j", nil], 
    # [:substrings, "cn", nil, "j", nil]]

    @logger.info filter

    unless filter
      @logger.info "Denying complex query (error 1): #{filter.inspect}"
      raise LDAP::ResultError::UnwillingToPerform, "This query is way too complex: #{filter.inspect}"
    end

    if filter[0] != :or
      @logger.info "Denying complex query (error 1): #{filter.inspect}"
      raise LDAP::ResultError::UnwillingToPerform, "This query is way too complex: #{filter.inspect}"
    end

    query = filter[1]

    if !(query.length > 3)
      @logger.info "Denying complex query (error 2): #{filter.inspect}"
      raise LDAP::ResultError::UnwillingToPerform, "This query is way too complex: #{filter.inspect}"      
    end
    
    if !query[1]
      @logger.info "Refusing to respond to blank query string: #{filter.inspect}."
      raise LDAP::ResultError::UnwillingToPerform, "Refusing to respond to blank query string: #{filter.inspect}"
    end

    if !(%w{mail cn givenname sn}.include? query[1].downcase)
      @logger.info "Denying complex query (error 3): #{filter.inspect}"
      raise LDAP::ResultError::UnwillingToPerform, "This query is way too complex: #{filter.inspect}"      
    end
    
    query_string = query[2..-1].compact.first # We're just going to take the first non-nil element as the search string
    
    if !query_string
      @logger.info "Refusing to respond to blank query string: #{filter.inspect}."
      raise LDAP::ResultError::UnwillingToPerform, "Refusing to respond to blank query string: #{filter.inspect}"
    end
    
    query_string
  end
end
