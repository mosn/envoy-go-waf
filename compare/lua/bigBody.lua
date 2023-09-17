function generateStringWithDigit6(length)
    local result = ""
    local digit = "6"

    for i = 1, length do
        result = result .. digit
    end

    return result
end

wrk.scheme = "http"
wrk.host = "localhost"
wrk.port = 10000
wrk.method = "POST"
wrk.body   = generateStringWithDigit6(100)
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"

request = function()
    path = "/testPost"
    return wrk.format(nil, path)
end



