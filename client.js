'use strict';
const common = require('./common'),
    extend = require('json-extend');

function Client(config) {
    this.config = config;
}

Client.prototype.scope = function() {
    return (['openid']).concat(this.config.scopes || []).join(' ');
};

Client.prototype.getTokens = function(req, callback) {
    let config = this.config,
        params = {
            grant_type: 'authorization_code',
            code: req.query.code,
            redirect_uri: this.callbackUrl(req)
        };

    getAccessToken(req.session, config, params, callback);
};

Client.prototype.getProfile = function(req, scopes, claims, callback) {
    let config = this.config,
        params = {
            scope: (scopes || []).concat(['openid']).join(' ')
        };

    if(claims) {
        params.claims = JSON.stringify(claims);
    }

    this.ensureActiveToken(req, function(err, bearerToken) {
        if(err) { return callback(err); }

        common.json('GET', common.addQuery(config.userinfo_endpoint, params), null, {
            Authorization: bearerToken
        }, callback);
    });
}

Client.prototype.ensureActiveToken = function(req, callback) {
    let tokens = req.session.tokens,
        config = this.config,
        params;

    function tokenHandle(err, tokens) {
        if(err) {
            callback(err);
        } else {
            callback(null, 'Bearer ' + tokens.access_token);
        }
    }

    if(tokens && Date.now() < tokens.expires_at) {
        tokenHandle(null, tokens);
    } else if(!tokens.refresh_token) {
        tokenHandle(new Error('No refresh token is present'));
    } else {
        params = {
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token,
            scope: this.scope()
        };

        getAccessToken(req.session, config, params, tokenHandle);
    }
};

Client.prototype.callbackUrl = function(req) {
    return common.resolveUrl(req, this.config.callback_url);
};

Client.prototype.authorizationUrl = function(req, state) {
    let config = this.config,
        params = extend({}, {
            state: state,
            response_type: 'code',
            client_id: config.client_id,
            redirect_uri: this.callbackUrl(req),
            scope: this.scope()
        }, config.authorize_params);

    return common.addQuery(config.authorization_endpoint, params);
};

Client.prototype.getEndSessionUrl = function(req) {
    let session = req.session,
        params = {
            id_token_hint: session.tokens.id_token,
            post_logout_redirect_uri: this.config.post_logout_redirect_uri || common.resolveUrl(req, '/')
        };

    return common.addQuery(this.config.end_session_endpoint, params);
};

function getAccessToken(session, config, params, callback) {
    extend(params, {
        client_id: config.client_id,
        client_secret: config.client_secret
    });

    common.form('POST', config.token_endpoint, params, null, function(err, data) {
        if(err) { return callback(err) }

        data = JSON.parse(data);
        data.expires_at = Date.now() + (data.expires_in * 1000) - common.timeout; // Take off a buffer so token won't expire mid call

        session.tokens = data;

        callback(null, data);
    });
}

module.exports = Client;
