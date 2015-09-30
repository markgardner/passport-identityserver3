# passport-identityserver3
Passport strategy for IdentityServer3 OpenID Connect Provider

### Strategy
This strategy supports AuthorizationCode flow.

```javascript
// Strategy allows you to overwrite the identifier. It will be 'identity3-oidc'
// by default if you only give the constructor the config object.
passport.use(new Identity3Strategy('custom_name', {
    configuration_endpoint: 'https://localhost:44333/.well-known/openid-configuration',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret',
    callback_url: '/login',
    scopes: ['profile', 'offline_access'],
    transformIdentity: function(identity) {
        return identity;
    },
    onEndSession: function(req, res) {
        // shouldn't end or write to res since the framework will be redirecting.
        // there just in case you need it.
    }
}));
```

### Single Sign out
This feature will redirect the user to identity server's logout feature to clear their SSO session

```javascript
// This will also destroy express sessions if they are present.
app.get('/logout', function(req, res) {
    passport._strategy('custom_name').endSession(req, res);
});
```

### Profile
You can get the current user's profile data with the following

```javascript
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
```