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
    return port.number == 3000 or shortport.http(port, host)
end 

-- Defines the action function
action = function(host, port)
    local results = {}

    for _, path in ipairs(paths) do
        -- Debugging: Indicate which path is being tested
        stdnse.print_debug(1, "Testing path: %s", path)
      

        local resp = http.get(host, port, path)

            if resp.status == 200 then 
                if resp.body then
                    local body_lower = resp.body:lower()
                    if body_lower:find("page not found") or
                       body_lower:find("not available") or
                       body_lower:find("doesn't exist") then -- Checks for common error messages
                        table.insert(results, path .. " returned a 200 OK but the page was not found") 
                    else
                        table.insert(results, path .. " returned HTTP 200 OK")
                    end
                end
            elseif resp.status == 401 or resp.status == 403 then
                table.insert(results, path .. " returned HTTP " .. resp.status)
            elseif resp.status == 302 then
                table.insert(results, path .. " redirected (302)")
            elseif resp.status == 301 then
                table.insert(results, path .. " permanently redirected (301)")
            elseif resp.status == 429 then
                table.insert(results, path .. " received HTTP 429 Too Many Requests")
            elseif resp.status == 500 then
                table.insert(results, path .. " received server error HTTP " .. resp.status)
                stdnse.print_debug(1, "Path '%s' returned status %d", path, resp.status) -- Debugging: Print response status
                stdnse.print_debug(1, "Path %s returned status %d", path, resp.status) -- Debugging: Print response status
            end
        end

    if #results > 0 then
        return table.concat(results, "\n")
    else
        return "No hidden paths found."
    end
end