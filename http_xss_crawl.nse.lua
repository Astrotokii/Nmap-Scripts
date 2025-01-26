description = [[
    Performs a vulnerability crawl to find possible XSS vulnerabilities.
]]

author = "Ryan LaPierre <Astro>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "vuln"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local url = require "url"

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

-- Run on port 3000 or if recognized as HTTP
portrule = function(host, port)
  return port.number == 3000 or shortport.http(host, port)
end 

action = function(host, port)
  local results = {}

  -- Crawl the site
  stdnse.print_debug(1, "Starting custom crawl on host=%s port=%d", host.ip, port.number)
  local depth = stdnse.get_script_args("http_xss_crawl.depth") or 2
  local pages = crawl(host, port, { path = "/", depth = tonumber(depth) })
  stdnse.print_debug(1, "Crawled %d pages", #pages)

  -- Check each page for XSS patterns
  -- List of patterns to identify potential XSS vulnerabilities.
  -- These patterns were chosen based on common XSS attack vectors and payloads.
  local xss_patterns = {
    "<script",                -- Script tag
    "javascript:",            -- JavaScript protocol
    "onerror=",               -- Event handler for onerror
    "onload=",                -- Event handler for onload
    "<img",                   -- Image tag
    "<iframe",                -- Iframe tag
    "%<%s*svg",               -- SVG tag
    "<object",                -- Object tag
    "document%.cookie",       -- Access to document cookie
    "window%.location",       -- Access to window location
    "alert%(",                -- Alert function
    "eval%(",                 -- Eval function
    "onmouseover=",           -- Event handler for mouse over
    "onfocus=",               -- Event handler for focus
    "onblur=",                -- Event handler for blur
    "onkeydown=",             -- Event handler for key down
    "onkeyup=",               -- Event handler for key up
    "onkeypress=",            -- Event handler for key press
    "onmousedown=",           -- Event handler for mouse down
    "onmouseup=",             -- Event handler for mouse up
    "onmousemove=",           -- Event handler for mouse move
    "onmouseout=",            -- Event handler for mouse out
    "onmouseenter=",          -- Event handler for mouse enter
    "onmouseleave=",          -- Event handler for mouse leave
    "onchange=",              -- Event handler for change
    "onsubmit=",              -- Event handler for form submit
    "onreset=",               -- Event handler for form reset
    "onselect=",              -- Event handler for text select
    "oncontextmenu=",         -- Event handler for context menu
    "innerHTML",              -- Access to inner HTML
    "outerHTML",              -- Access to outer HTML
    "createElement",          -- Creating new HTML elements
    "appendChild",            -- Appending child elements
    "insertBefore",           -- Inserting elements before another
    "setAttribute",           -- Setting attributes
    "getAttribute",           -- Getting attributes
    "localStorage",           -- Access to local storage
    "sessionStorage",         -- Access to session storage
    "XMLHttpRequest",         -- Making HTTP requests
    "fetch(",                 -- Fetch API for making HTTP requests
    "importScripts(",         -- Importing scripts in web workers
    "Function(",              -- Creating new functions
    "setTimeout(",            -- Setting a timeout
    "setInterval(",           -- Setting an interval
    "location.href",          -- Accessing location href
    "location.replace",       -- Replacing location
    "location.assign",        -- Assigning location
    "history.pushState",      -- Manipulating history state
    "history.replaceState" 
  }

  for _, page in ipairs(pages) do
    stdnse.print_debug(1, "Analyzing page: %s (status %d)", page.url, page.status)
    if page.status == 200 and page.body then
      local body_lower = page.body:lower()
      for _, pattern in ipairs(xss_patterns) do
        if body_lower:find(pattern) then
          table.insert(results, ("Potential XSS pattern vulnerability %q found at path %s"):format(pattern, page.url))
        end
      end
    else
      table.insert(results, ("Skipped page %s received status %d"):format(page.url, page.status))
    end
  end

  -- Final output
  if #results == 0 then
    table.insert(results, "No potential XSS found.")
  end

  return stdnse.format_output(true, results)
end
