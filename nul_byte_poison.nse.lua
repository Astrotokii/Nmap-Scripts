description = [[
  This test checks that the server is able to handle a request with a null byte
  in the URL. This is a common attack vector for web servers, and the server
  should be able to handle it gracefully.
]]

author = "Ryan LaPierre <Astro>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "exploit", "vuln"}

-- This test is only relevant for HTTP servers
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"
-- Run on port 3000 or if recognized as HTTP
portrule = function(host, port)
    return port.number == 3000 or shortport.http(host, port)
  end 
  


-- Utility: extract links from a page using a naive pattern match.
local function extract_links(body)
    local links = {}
    -- This pattern is simplistic: it looks for href="...". 
    for link in body:gmatch('href%s*=%s*"([^"]+)"') do
      table.insert(links, link)
    end
    return links
  end
  
  -- Recursive internal function for crawling
  local function crawl_internal(host, port, start_path, max_depth, visited, pages)
   -- Immediately debug + skip if 'start_path' isn't a string
    stdnse.print_debug(1,
      "DEBUG: entering crawl_internal with start_path type='%s' val='%s'",
      type(start_path),
      tostring(start_path)
    )
  
    if type(start_path) ~= "string" then
      stdnse.print_debug(1, "WARNING: 'start_path' is a table or nil, skipping!")
      return
    end
  
    if visited[start_path] then
      return
    end
    visited[start_path] = true
  
    local resp = http.get(host, port, start_path )
    if not resp or not resp.body then
      return
    end
  
    table.insert(pages, {
      url = start_path,
      status = resp.status,
      body = resp.body
    })
  
    if max_depth <= 0 then
      return
    end
  
    local found_links = extract_links(resp.body)
  
    for _, link in ipairs(found_links) do
    stdnse.print_debug(1, "DEBUG: Found raw link: '%s'", link)
  
  local base_url = ("http://%s:%d%s"):format(host.ip, port.number, start_path)
    local absolute_url = url.absolute(base_url, link)
  
    stdnse.print_debug(1, "DEBUG: base_url='%s' + link='%s' => absolute_url='%s'", base_url, link, absolute_url)
  
    local parsed = url.parse(absolute_url)
    if not parsed then
      stdnse.print_debug(1, "DEBUG: url.parse() returned nil for '%s'", absolute_url)
      goto continue
    end
  
    stdnse.print_debug(1, "DEBUG: parsed = %s", tostring(parsed))
  
    if parsed.host and parsed.host ~= host then
      stdnse.print_debug(1, "DEBUG: skipping link with different host '%s'", parsed.host)
      goto continue
    end
  
    local p = parsed.path
    stdnse.print_debug(1, "DEBUG: parsed.path type='%s' value='%s'", type(p), tostring(p))
  
    -- If path is invalid, skip
    if not p or type(p) ~= "string" or p == "" then
      p = "/"
    end
  
    local q = parsed.query
    if type(q) ~= "string" then
      q = nil
    end
  
    local path = p
    if q then
      path = path .. "?" .. q
    end
  
    crawl_internal(host, port, path, max_depth - 1, visited, pages)
    ::continue::
  end
  end
  
  -- Public-facing function to start crawling
  local function crawl(host, port, options)
    local paths = (options and options.path) or "/"
    local depth = (options and options.depth) or 2
  
    local visited = {}
    local pages = {}
    crawl_internal(host, port, paths, depth, visited, pages)
    return pages
  end
  
  action = function(host, port)
    local results = {}
    local pages = crawl(host, port)

    local options = {
      argument = stdnse.get_script_args("argument") or "%00",
      path = stdnse.get_script_args("path") or "/",
      depth = tonumber(stdnse.get_script_args("depth")) or 2
    }
    local path = options.path
    
    for _, pageInfo in ipairs(pages) do
      local normalPath = pageInfo.url
        local normal_resp = http.get(host, port, normalPath)

      if normal_resp and normal_resp.status then
        -- Build a small injection: "param=foo%00bar"
        local injected_path = normalPath
        
        local separator = normalPath:find("%?") and "&" or "?"
        injected_path = injected_path .. separator .. options.argument

    -- Send the request
    local injected_resp = http.get(host, port, injected_path)

    -- Check the responses
    if injected_resp and injected_resp.status then
        if (injected_resp.status ~= normal_resp.status) then
            table.insert(results,
        ("[Potential Null-Byte} Path=%s =. normal status=%d, injected status=%d")
        :format(path, normal_resp.status, injected_resp.status))
        else
            local normal_snip = normal_resp.body and normal_resp.body:sub(1, 200)
            local injected_snip = injected_resp.body and injected_resp.body:sub(1, 200)
            if normal_snip ~= injected_snip then
                table.insert(results,
                ("[Potential Null-Byte] Path=%s => normal and injected bodies differ")
                :format(normalPath))
            end
        end
    else
        table.insert(results,
        ("[Error] Could not fetch injected path %s")):format(injected_path)
    end
  else
    table.insert(results,
    ("[Error] Could not fetch normal path %s")):format(normalPath)
  end
 end

if #results == 0 then
    table.insert(results, "No null-byte injection vulnerabilities found")
end
return stdnse.format_output(true, results)
end