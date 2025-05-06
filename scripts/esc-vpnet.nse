local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects devices supporting the ESC/VP.net protocol.
Sends a specific ESC/VP.net message and parses the response.
]]

author = "Jaroslav Svoboda"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({3629}, "escvpnet")

action = function(host, port)
    local socket = nmap.new_socket()
    local status, err

    -- Define the ESC/VP.net message
    local message = "ESC/VP.net\x10\x03\x00\x00\x00\x00"

    -- Try to connect to the target
    status, err = socket:connect(host, port)
    if not status then
        return "Failed to connect: " .. err
    else
        stdnse.print_debug(1, "Connected to " .. host.ip .. ":" .. port.number)
    end

    -- Send the ESC/VP.net message
    status, err = socket:send(message)
    if not status then
        socket:close()
        return "Failed to send message: " .. err
    else
        stdnse.print_debug(1, "Message sent: " .. stdnse.tohex(message))
    end

    -- Receive the response
    local response, err = socket:receive_bytes(1024)
    if response and type(response) == "string" then
        stdnse.print_debug(1, "Raw response received: " .. stdnse.tohex(response))
    elseif err and type(err) == "string" then
        stdnse.print_debug(1, "Error receiving response, but treating as response: " .. err)
        response = err  -- Treat the error message as the response
    else
        stdnse.print_debug(1, "No response received.")
    end

    socket:close()

    if response and type(response) == "string" then
        return "ESC/VP.net detected. Response: " .. stdnse.tohex(response)
    elseif response == nil then
        return "Error receiving response: " .. err
    else
        return "No response received."
    end
end