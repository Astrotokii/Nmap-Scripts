description = [[
    This script uses HTTP GET requests to find hidden URL paths on a web server.
]]

author = "Ryan LaPierre <Astro>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "brute"}

-- Imports necessary libraries
local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

-- Defines the list of common path extensions to check
local paths = {
    "/admin",
    "/administrator",
    "/administration",
    "/login",
    "/hidden",
    "/secret",
    "/backup",
    "/test",
    "/old",
    "/private",
    "/dev",
    "/tmp",
    "/logs",
    "/config",
    "/conf",
    "/backups",
    "/db",
    "/database",
    "/data",
    "/info",
    "/information",
    "/debug",
    "/debugging",
    "/tests",
    "/temp",
    "/ftp",
}

portrule = function(host, port)
    return port.number == 3000 or shortport.http(host, port)
end 

-- Defines the action function
action = function(host, port)
    local results = {}

    for _, path in ipairs(paths) do
        -- Debugging: Indicate which path is being tested
        stdnse.print_debug(1, "Testing path: %s", path)
      

        local ok, resp

        -- If the request went through:
        if ok and resp then
            -- Debugging: Print response status
            stdnse.print_debug(1, "Path %s returned status %d", path, resp.status or -1)
            stdnse.print_debug(1, "Response body for path %s: %s", path, resp.body or "No body")
          
            if resp.status == 200 then 
                if resp.body and (
                    resp.body:lower():find("page not found") or
                    resp.body:lower():find("not available") or
                    resp.body:lower():find("doesn't exist")
                ) then -- Checks for common error messages
                    table.insert(results, path .. " returned a 200 OK but the page was not found") 
                else
                    table.insert(results, path .. " returned HTTP 200 OK")
                end
            elseif resp.status == 401 or resp.status == 403 then
                table.insert(results, path .. " returned HTTP " .. resp.status)
            elseif resp.status == 302 then
                table.insert(results, path .. " redirected (302)")
            elseif resp.status == 301 then
                table.insert(results, path .. " permanently redirected (301)")
            elseif resp.status == 429 then
                table.insert(results, path .. " received HTTP 429 Too Many Requests")
            elseif resp.status >= 500 then
                table.insert(results, path .. " received server error HTTP " .. resp.status)
            else
                stdnse.print_debug(1, "Path %s returned status %d", path, resp.status) -- Debugging: Print response status
            end
        end
    end

    if #results > 0 then
        return stdnse.format_output(
            true,
            "Found paths:",
            table.concat(results, "\n")
        )
    else
        return "No hidden paths found."
    end
end