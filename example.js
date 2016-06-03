var express = require('express'),
    session = require('express-session'),
    passport = require('passport'),
    Identity3Strategy = require('./strategy'),
    Client = require('./client');

// Don't leave this in your production app
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

var app = express();

app.use(session({ secret: 'keyboard mouse' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
    if(!req.isAuthenticated() && !req.url.match(/^\/login/)) {
        res.redirect('/login');
    } else {
        next();
    }
});

app.get('/', function(req, res) {
    var strategy = passport._strategy('custom_name'),
        profileScopes = ['profile'],
        additionalClaims = null; // Optionally you can specify specific claims to request as an array of string.

    res.writeHead(200, {
        'Content-Type': 'text/html'
    });
    
    strategy.profile(req, profileScopes, additionalClaims, function(err, profile) {
        res.end('<html><body>Logged in, <a href="/logout">Logout</a><pre>' + JSON.stringify(profile, null, 2) + '</pre></body></html>');
    });
});

app.get('/login', 
    passport.authenticate('custom_name', { failureRedirect: '/login' }),
    function(req, res) { // Successful login handler, just redirect to homepage
        res.redirect('/');
    });

app.get('/logout', function(req, res) {
    passport._strategy('custom_name').endSession(req, res);
});

// Strategy allows you to overwrite the identifier. It will be 'identity3-oidc' by default if you only give the constructor the config object.
passport.use(new Identity3Strategy('custom_name', {
    configuration_endpoint: 'https://localhost:44333/.well-known/openid-configuration',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret',
    callback_url: '/login',
    scopes: ['profile', 'offline_access'],
    // This optional jwt config will be sent to jsonwebtoken to validate the request's access token
    jwt: {
        audience: 'your_client_id',

        ignoreNotBefore: true,
        clockTolerance: 60
    },
    transformIdentity: function(identity) {
        return identity;
    },
    onEndSession: function(req, res) {
        // shouldn't end or write to res since the framework will be redirecting.
        // there just in case you need it.
    }
}));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.listen(8001);