'use strict';

var directives = angular.module('oauth.directive', []);

directives.directive('oauth', [
  'IdToken',
  'AccessToken',
  'Endpoint',
  'Profile',
  'Storage',
  '$location',
  '$rootScope',
  '$compile',
  '$http',
  '$templateCache',
  function(IdToken, AccessToken, Endpoint, Profile, Storage, $location, $rootScope, $compile, $http, $templateCache) {

    var definition = {
      restrict: 'AE',
      replace: true,
      scope: {
        site: '@',          // (required) set the oauth server host (e.g. http://oauth.example.com)
        clientId: '@',      // (required) client id
        redirectUri: '@',   // (required) client redirect uri
        responseType: '@',  // (optional) response type, defaults to token (use 'token' for implicit flow and 'code' for authorization code flow
        scope: '@',         // (optional) scope
        profileUri: '@',    // (optional) user profile uri (e.g http://example.com/me)
        template: '@',      // (optional) template to render (e.g views/templates/default.html)
        text: '@',          // (optional) login text
        authorizePath: '@', // (optional) authorization url
        revokePath: '@',    // (optional) revoke token path
        logoutPath: '@',    // (optional) logout path
        state: '@',         // (optional) An arbitrary unique string created by your app to guard against Cross-site Request Forgery
        storage: '@',        // (optional) Store token in 'sessionStorage' or 'localStorage', defaults to 'sessionStorage'
        nonce: '@',          // (optional) Send nonce on auth request
                             // OpenID Connect extras, more details in id-token.js:
        issuer: '@',         // (optional for OpenID Connect) issuer of the id_token, should match the 'iss' claim in id_token payload
        subject: '@',        // (optional for OpenID Connect) subject of the id_token, should match the 'sub' claim in id_token payload
        pubKey: '@'          // (optional for OpenID Connect) the public key(RSA public key or X509 certificate in PEM format) to verify the signature
      }
    };

    definition.link = function postLink(scope, element) {
      scope.show = 'none';

      scope.$watch('clientId', function() {
        init();
      });

      var init = function() {
        initAttributes();          // sets defaults
        Storage.use(scope.storage);// set storage
        if (scope.template) {
          compile();                 // compiles the desired layout
        }
        Endpoint.set(scope);       // sets the oauth authorization url
        IdToken.set(scope);
        AccessToken.set(scope);    // sets the access token object (if existing, from fragment or session)
        initProfile(scope);        // gets the profile resource (if existing the access token)
        initView();                // sets the view (logged in or out)
      };

      var initAttributes = function() {
        scope.authorizePath = scope.authorizePath || '/oauth/authorize';
        scope.tokenPath     = scope.tokenPath     || '/oauth/token';
        scope.revokePath    = scope.revokePath    || undefined;
        scope.logoutPath    = scope.logoutPath    || undefined;
        scope.template      = scope.template      || undefined; // was default to 'views/templates/default.html';
        scope.responseType  = scope.responseType  || 'id_token token';
        scope.text          = scope.text          || 'Sign In';
        scope.state         = scope.state         || undefined;
        scope.scope         = scope.scope         || undefined;
        scope.storage       = scope.storage       || 'sessionStorage';
        scope.nonce         = scope.nonce         || true; //use nonce or not. If true(by default) then random nonce generation and validation will be taken care by oauth-ng
      };

      var compile = function() {
        $http.get(scope.template, { cache: $templateCache }).success(function(html) {
          element.html(html);
          $compile(element.contents())(scope);
        });
      };

      var initProfile = function(scope) {
        var token = AccessToken.get();

        if (token && token.access_token && scope.profileUri) {
          Profile.find(scope.profileUri).success(function(response) {
            scope.profile = response;
          });
        }
      };

      var initView = function() {
        var token = AccessToken.get();

        if (!token) {
          return loggedOut(); // without access token it's logged out
        }
        if (token.access_token) {
          return authorized(); // if there is the access token we are done
        }
        if (token.error) {
          return denied(); // if the request has been denied we fire the denied event
        }
      };

      scope.login = function() {
        Endpoint.redirect();
      };

      scope.logout = function() {
        AccessToken.destroy(scope);
        $rootScope.$broadcast('oauth:logout');
        loggedOut();
      };

      scope.$on('oauth:expired', function() {
        AccessToken.destroy(scope);
        scope.show = 'logged-out';
      });

      // user is authorized
      var authorized = function() {
        $rootScope.$broadcast('oauth:authorized', AccessToken.get());
        scope.show = 'logged-in';
      };

      // set the oauth directive to the logged-out status
      var loggedOut = function() {
        $rootScope.$broadcast('oauth:loggedOut');
        scope.show = 'logged-out';
      };

      // set the oauth directive to the denied status
      var denied = function() {
        scope.show = 'denied';
        $rootScope.$broadcast('oauth:denied');
      };

      // Updates the template at runtime
      scope.$on('oauth:template:update', function(event, template) {
        scope.template = template;
        compile(scope);
      });

      // Hack to update the directive content on logout
      // TODO think to a cleaner solution
      scope.$on('$routeChangeSuccess', function () {
        init();
      });

      scope.$on('$stateChangeSuccess', function () {
        init();
      });
    };

    return definition;
  }
]);
