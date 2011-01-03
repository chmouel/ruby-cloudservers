module CloudServers
  class Authentication
    
    # Performs an authentication to the Rackspace Cloud authorization servers.  Opens a new HTTP connection to the API server,
    # sends the credentials, and looks for a successful authentication.  If it succeeds, it sets the svrmgmthost,
    # svrmgtpath, svrmgmtport, svrmgmtscheme, authtoken, and authok variables on the connection.  If it fails, it raises
    # an exception.
    #
    # Should probably never be called directly.
    def initialize(connection)
      parsed_authurl = URI.parse(connection.authurl)
      path = parsed_authurl.path      
      hdrhash = { "X-Auth-User" => connection.authuser, "X-Auth-Key" => connection.authkey }
      begin
        server             = get_server(connection, parsed_authurl)
        
        server.use_ssl = true
        server.verify_mode = OpenSSL::SSL::VERIFY_NONE
        server.start
      rescue
        raise CloudServers::Exception::Connection, "Unable to connect to #{server}"
      end
      response = server.get(path,hdrhash)
      if (response.code == "204")
        connection.authtoken = response["x-auth-token"]
        connection.svrmgmthost = URI.parse(response["x-server-management-url"]).host
        connection.svrmgmtpath = URI.parse(response["x-server-management-url"]).path
        # Force the path into the v1.0 URL space
        connection.svrmgmtpath.sub!(/\/.*?\//, '/v1.0/')
        connection.svrmgmtport = URI.parse(response["x-server-management-url"]).port
        connection.svrmgmtscheme = URI.parse(response["x-server-management-url"]).scheme
        connection.authok = true
      else
        connection.authtoken = false
        raise CloudServers::Exception::Authentication, "Authentication failed with response code #{response.code}"
      end
      server.finish
    end

    private

    def get_server(connection, parsed_authurl)
      Net::HTTP::Proxy(connection.proxy_host, connection.proxy_port).new(parsed_authurl.host,parsed_authurl.port)
    end
    
  end
end
