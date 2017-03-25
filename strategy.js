'use strict';
const passport = require('passport'),
    jwt = require('jsonwebtoken'),
    extend = require('json-extend'),
    common = require('./common'),
    Client = require('./client');

function Strategy(identifier, config) {
    if(typeof(identifier) === 'object') {
        config = identifier;
        identifier = 'identity3-oidc';
    }

    if(!config || !config.client_id || !config.client_secret || !config.callback_url) {
        throw new Error('The required config settings are not present [client_id, client_secret, callback_url]');
    }

    if(!config.jwt) {
        config.jwt = {
            audience: config.audience || config.client_id,
            issuer: config.issuer,
            ignoreNotBefore: config.ignoreNotBefore || false,
            ignoreExpiration: config.ignoreExpiration || false
        };
    }

    passport.Strategy.call(this);

    this.name = identifier;
    this.config = config;
    this.client = new Client(config);

    if(config.configuration_endpoint) {
        this.discover(config);
    }
}

require('util').inherits(Strategy, passport.Strategy);

/*********** Passport Strategy Impl ***********/

Strategy.prototype.authenticate = function(req, options) {
    if(req.query.error) {
        return this.error(new Error(req.query.error));
    } else if(req.query.code) {
        if(!req.session.tokens || req.query.state !== req.session.tokens.state) {
            return this.error(new Error('State does not match session.'));
        }

        let self = this,
            config = self.config;

        this.client.getTokens(req, function(err, data) {
            let user;

            if(err) {
                self.error(err);
            } else if(user = self.validateToken(data.id_token)) {
                if(config.transformIdentity) {
                    if(config.transformIdentity.length === 1) {
                        user = config.transformIdentity(user);

                        self.success(user);
                    } else {
                        config.transformIdentity(user, self.success, self.error);
                    }
                } else {
                    self.success(user);
                }
            } else {
                req.session.tokens = null;
            }
        });
    } else {
        let state = common.randomHex(16);

        req.session.tokens = {
            state: state
        };

        this.redirect(this.client.authorizationUrl(req, state));
    }
};

/*********** End Passport Strategy Impl ***********/

// 5.3.  UserInfo Endpoint [http://openid.net/specs/openid-connect-core-1_0.html#UserInfo]
Strategy.prototype.profile = function(req, scopes, claims, callback) {
    this.client.getProfile(req, scopes, claims, callback);
};

// 5.  RP-Initiated Logout [http://openid.net/specs/openid-connect-session-1_0.html#RPLogout]
Strategy.prototype.endSession = function(req, res) {
    let endSessionUrl = this.client.getEndSessionUrl(req);

    // Clean up session for passport just in case express session is not being used.
    req.logout();
    req.session.tokens = null;

    // Destroy express session if possible
    if(req.session && req.session.destroy) {
        req.session.destroy();
    }

    // Allow app to do some cleanup if needed
    if(this.config.onEndSession) {
        this.config.onEndSession(req, res);
    }

    res.redirect(endSessionUrl);
};

// 3.1.3.7.  ID Token Validation [http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation]
Strategy.prototype.validateToken = function(token) {
    try {
        let cert;

        if(!this.config.keys || !this.config.keys.length) {
            this.error(new Error('No keys configured for verifying tokens'));

            return false;
        }

        cert = common.formatCert(this.config.keys[0].x5c[0]);

        return jwt.verify(token, cert, this.config.jwt);
    } catch (e) {
        this.error(e);
    }
};

// 4.  Obtaining OpenID Provider Configuration Information [http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig]
Strategy.prototype.discover = function(config) {
    let self = this,
        origAuth = self.authenticate,
        pendingAuth = [];

    // overwrite authentication to pause the auth requests while we are discovering.
    self.authenticate = function(req, options) {
        pendingAuth.push([this, req, options]);
    };

    common.json('GET', config.configuration_endpoint, null, null, function(err, data) {
        if(err) { throw err; }

        extend(config, data);

        if(config.jwt) {
            config.jwt.issuer = config.issuer;
        }

        common.json('GET', data.jwks_uri, null, null, function(err, data) {
            if(err) { throw err; }

            extend(config, data);

            self.authenticate = origAuth;

            pendingAuth.forEach(function(pending) {
                let self = pending.shift();

                origAuth.apply(self, pending);
            });

            // Remove refs to allow gc.
            pendingAuth = null;
        });
    });
};

module.exports = Strategy;
