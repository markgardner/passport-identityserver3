var crypto = require('crypto'),
    url = require('url'),
    qs = require('querystring'),
    extend = require('json-extend');

var agents = {
    'http:': require('http'),
    'https:': require('https')
};

function request(method, requestedUrl, headers, body, callback) {
    var parsedUrl = url.parse(requestedUrl);

    var req = agents[parsedUrl.protocol].request({
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        headers: headers,
        path: parsedUrl.pathname,
        method: method
    }, function(res) {
        var data = '';

        res.on('data', function(chunk) {
            data += chunk;
        });

        res.on('end', function() {
            callback(null, data);
        });
    });

    req.setTimeout(instance.timeout, function() {
        callback(new Error('Request timed out.'));
    });

    if(body) {
        req.end(body);
    } else {
        req.end();
    }
}

var instance = module.exports = {
    timeout: 10000,
    addQuery: function(url, params) {
        var joinChar = ~url.indexOf('?') ? '&' : '?';

        return url + joinChar + qs.stringify(params);
    },
    formatCert: function(x5c) {
        var parts = ['-----BEGIN CERTIFICATE-----'];

        while(x5c.length) {
            parts.push(x5c.slice(0, 64));

            x5c = x5c.slice(64);
        }

        parts.push('-----END CERTIFICATE-----\n');

        return parts.join('\n');
    },
    randomHex: function(numOfChars) {
        return crypto.randomBytes(numOfChars).toString('hex');
    },
    resolveUrl: function(req, absoluteOrRelative) {
        var headers = req.headers,
            protocol = headers['x-forwarded-proto'] || (req.connection.encrypted ? 'https' : 'http'),
            host = headers.host,
            path = req.url,
            parsed = url.parse(absoluteOrRelative);

        if(parsed.protocol) {
            return absoluteOrRelative;
        } else {
            return url.resolve(protocol + '://' + host + path, absoluteOrRelative);
        }
    },
    form: function(method, requestedUrl, body, headers, callback) {
        extend(headers || (headers = {}), {
            'Content-Type': 'application/x-www-form-urlencoded'
        });

        if(body) {
            body = qs.stringify(body);
        }

        request(method, requestedUrl, headers, body, callback);
    },
    json: function(method, requestedUrl, body, headers, callback) {
        extend(headers || (headers = {}), {
            Accept: 'application/json'
        });

        if(body) {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify(body);
        }

        request(method, requestedUrl, headers, body, function(err, data) {
            if(!err && data) {
                data = JSON.parse(data);
            }

            callback(err, data);
        });
    }
};