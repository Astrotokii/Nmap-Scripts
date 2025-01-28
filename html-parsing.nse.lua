description = [[
    This is a script/library that attempts to parse HTML files and extract the text content.
]]

author = "Ryan LaPierre <Astro>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln"}


local http = require("http")
local shortport = require("shortport")
local stdnse = require("stdnse")
local url  = require("url")
local table = require("table")

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
    local path = (options and options.path) or "/"
    local depth = (options and options.depth) or 2
  
    local visited = {}
    local pages = {}
    crawl_internal(host, port, path, depth, visited, pages)
    return pages
  end

  action = function(host, port)
    local results = {}
    local options = {
        path = stdnse.get_script_args("path") or "/",
        depth = tonumber(stdnse.get_script_args("depth")) or 2
      }
    local path = options.path
    local depth = options.depth

    -- Crawl the site
    stdnse.print_debug(1, "Starting custom crawl on host=%s port=%d", host.ip, port.number)
    local depth = stdnse.get_script_args("http_xss_crawl.depth") or 2
    local pages = crawl(host, port, { path, depth})
    stdnse.print_debug(1, "Crawled %d pages", #pages)
  


-- Iterate over crawled pages, extract links and content 
for _, page in ipairs(pages) do
    local html_content = page.body
    local links = extract_links(html_content)
    for _, link in ipairs(links) do
        table.insert(results, link)
        table.insert(results, html_content)
    end
end

return stdnse.format_output(true, results)
end