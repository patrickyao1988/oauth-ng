describe('IdToken', function() {

  var Storage, IdToken;

  var publicKeyString;
  var validIdToken, invalidIdToken;
  var validAccessToken;

  beforeEach(module('oauth'));

  beforeEach(inject(function ($injector) {
    Storage = $injector.get('Storage');
  }));
  beforeEach(inject(function ($injector) {
    IdToken = $injector.get('IdToken');
  }));

  beforeEach(function () {
    /**
     * http://kjur.github.io/jsjws/tool_jwt.html generated sample id_token, signed by default private key
     * The public key is shown as below
     */
    publicKeyString =
        "-----BEGIN PUBLIC KEY-----\n"
        + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA33TqqLR3eeUmDtHS89qF\n"
        + "3p4MP7Wfqt2Zjj3lZjLjjCGDvwr9cJNlNDiuKboODgUiT4ZdPWbOiMAfDcDzlOxA\n"
        + "04DDnEFGAf+kDQiNSe2ZtqC7bnIc8+KSG/qOGQIVaay4Ucr6ovDkykO5Hxn7OU7s\n"
        + "Jp9TP9H0JH8zMQA6YzijYH9LsupTerrY3U6zyihVEDXXOv08vBHk50BMFJbE9iwF\n"
        + "wnxCsU5+UZUZYw87Uu0n4LPFS9BT8tUIvAfnRXIEWCha3KbFWmdZQZlyrFw0buUE\n"
        + "f0YN3/Q0auBkdbDR/ES2PbgKTJdkjc/rEeM0TxvOUf7HuUNOhrtAVEN1D5uuxE1W\n"
        + "SwIDAQAB"
        + "-----END PUBLIC KEY-----\n";
  });

  describe('validate an id_token with both signature and claims', function() {
    beforeEach(function () {
      /*
        Valid token with RS256, expires at 20251231235959Z UTC
        https://jwt.io has a debugger that can help view the id_token's header and payload

        e.g. The header of following token is { "alg": "RS256", "typ": "JWT" }
             The body of the following token is:
             {
               "iss": "oidc",
               "sub": "oauth-ng-client",
               "nbf": 1449267385,
               "exp": 1767225599,
               "iat": 1449267385,
               "jti": "id123456",
               "typ": "https://example.com/register"
             }
       */
      validIdToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
          '.eyJpc3MiOiJvaWRjIiwic3ViIjoib2F1dGgtbmctY2xpZW50IiwibmJmIjoxNDQ5MjY3Mzg1LCJleHAiOjE3NjcyMjU1OTksImlhdCI6MTQ0OTI2NzM4NSwianRpIjoiaWQxMjM0NTYiLCJ0eXAiOiJodHRwczovL2V4YW1wbGUuY29tL3JlZ2lzdGVyIn0' +
          '.MXBbWkr1Sf6KRn11IgEXyVg5g5VVUOSyLhTglgL8fI13aGf6SquVy0ZNn7ajTym5a_fJHPWLlgpvo-v98xuMBC9cLH_NN3ocrZAQkkW19G4AVY-LsOURp0t9JzVEb-pEe8Zps8O7Mumj0qSlr-4Dnyb3UMqdwZTcSgUTrbdyf6Qa7KHA0myANLDs2T8ctlSEptgVHPj8Zy9tk9UUlDZgsU4KoEpanDt7c1GzQJu7KEI3iJYlVEwDgMqu0EWn64aaP-w1OKZAyHbJWdMwun7i9edLonQ37M67Mb8ox6-cx8fxS3s3h6b3jRS5L0RACFVtB9lF4f_0yPVBwcTBhzYBOg';

      IdToken.set({
        issuer: 'oidc',
        clientId: 'oauth-ng-client',
        pubKey: publicKeyString
      });
    });

    it('with success', function () {
      expect(IdToken.validateIdToken(validIdToken)).toEqual(true);
    });

  });

  describe('verify id_token signature with algorithm', function () {

    describe('RS256', function () {

      beforeEach(function () {

        //Valid token with RS256, expires at 20251231235959Z UTC
        validIdToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLXJzLTI1NiIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ0OTE0NCwiZXhwIjoxNzY3MjI1NTk5LCJpYXQiOjE0NDk0NDkxNDQsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.lpxeRY_IqsvgWLj6H2ghre8dBBtsSF-bnjWHtVvhQIuerztMQOX20CCqtVFGScIZcI4gHxtEZGauF-sX3zwaLuqPtzORjaBiH0vV6C-3ZyqZrCU_n-TozKAwpSYyyHQpJ-xKdGRaOdd7_4vDtaFBWyHLXp1hbYvMftkPCvGjO25GppGQ7MjxCnd7IAPn0obXx2lZr1q0hHT7532O5dlmsPHTyrTvrSupTOVH3CZe3ZghM6R_mlagyfRh1Pf2cdRQkXJ0gEHf4GYpBbz-E3YfCyxcvQRPzfKnpLGH16M1_jM0mc3z5zVsegi62NNr79B8hExG5OtXfDMvws4LDfps2A';

        IdToken.set({
          issuer: 'oidc-rs-256',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });
      });

      it('validate token successfully', function () {
        expect(IdToken.verifyIdTokenSig(validIdToken)).toEqual(true);
      });

    });

    describe('RS384', function () {

      beforeEach(function() {
        //Valid token with RS384, expires at 20251231235959Z UTC
        validIdToken = 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLXJzLTM4NCIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ0NTM3NSwiZXhwIjoxNzY3MjI1NTk5LCJpYXQiOjE0NDk0NDUzNzUsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.cDSfORFIZ28nUgvbdJ0wwe-JtZOy5J40--xYfJBPbwRJz02EscFlRD-xNqRB9eEsVVK4shW9AtF4yfp3Sa_jcjziGlQNwpRzFhnCqrADupMNNhK-z1SmuxgG_zfP7plXVAhg1IJ671w43I2PmXQw5wAKpAMwun4J-mxHP7ZV6__z_hxv4QclONHrk23_ebHJXi8W4q7B7n-amQQZ-kKQf8OblZIX9kAF58WIhyA5ZNqXGZ_hmcDKUVlBpgiurpD8u429NwrlauowHCQI_zMKlaEzJvH5qNhXLNbFgLmhrQFYo_VW48ZjHygmAkuuKt0jioR0dUeYirTGq-xEBcOpnw';

        IdToken.set({
          issuer: 'oidc-rs-384',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });

      });

      it('validate token successfully', function () {
        expect(IdToken.verifyIdTokenSig(validIdToken)).toEqual(true);
      });

    });

    describe('RS512', function () {

      beforeEach(function() {
        //Valid token with RS512, expires at 20251231235959Z UTC
        validIdToken = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLXJzLTUxMiIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ0NzQyMiwiZXhwIjoxNzY3MjI1NTk5LCJpYXQiOjE0NDk0NDc0MjIsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.BAqggV91_YwQmnKty-qHzi61WgUpLue7gFWDe72VzHzcQhYu1STLduBxtr3qtsl6XzVDL6N0AmYfpFwMQQ8dRMaLLsnx6wg7Mi9nqCkDTL1Px5biL9AM4C3S32N6iJ4nFyJgUiFJ4RWG9f-78k4PG51xvSCkA-2TbODU1KsXRnc3o9SrQKw8pWnjmxNIfDtfzkxEdBlePWuknZGeaJBlR4hBRrxH1GnNDVW3aeuLJl4y1IOIbUxsnNW8HgAm6KpoCVAbPN7YzQPfDEIQgaNSS_i7Nkuq9Rno_6ivfqxs3QCiEqHJkAh8W2J3N8iPpRrCW03oQp2sGvmRTxxvxuxZbw'

        IdToken.set({
          issuer: 'oidc-rs-512',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });

      });

      it('validate token successfully', function () {
        expect(IdToken.verifyIdTokenSig(validIdToken)).toEqual(true);
      });

    });

  });


  describe('validate access_token with id_token header information', function () {

    beforeEach(function() {
      /*
       Sample id_token and access_token pair (corresponds to response_type = 'id_token token'
       Get more examples at google playground: https://developers.google.com/oauthplayground/
       */
      validIdToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjJhODc0MjBlY2YxNGU5MzRmOWY5MDRhMDE0NzY4MTMyMDNiMzk5NGIifQ' +
          '.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTEwMTY5NDg0NDc0Mzg2Mjc2MzM0IiwiYXpwIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXRfaGFzaCI6ImFVQWtKRy11Nng0UlRXdUlMV3ktQ0EiLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0MzIwODI4NzgsImV4cCI6MTQzMjA4NjQ3OH0' +
          '.xSwhf4KvEztFFhVj4YdgKFOC8aPEoLAAZcXDWIh6YBXpfjzfnwYhaQgsmCofzOl53yirpbj5h7Om5570yzlUziP5TYNIqrA3Nyaj60-ZyXY2JMIBWYYMr3SRyhXdW0Dp71tZ5IaxMFlS8fc0MhSx55ZNrCV-3qmkTLeTTY1_4Jc';
      validAccessToken = 'ya29.eQETFbFOkAs8nWHcmYXKwEi0Zz46NfsrUU_KuQLOLTwWS40y6Fb99aVzEXC0U14m61lcPMIr1hEIBA';
    });

    it('should succeed', function() {
      expect(IdToken.validateAccessToken(validIdToken, validAccessToken)).toEqual(true);
    })
  });


  describe('detect false id_token with', function () {

    describe('wrong issuer', function () {

      beforeEach(function () {
        //Id token with issuer as 'oidc-foo'
        invalidIdToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLWZvbyIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ0OTYyNCwiZXhwIjoxNzY3MjI1NTk5LCJpYXQiOjE0NDk0NDk2MjQsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.UCDvdOtXzXeDReumQsj-WXEgUIs_PyTdVt94n52hZT9q3Rfs4jFkx64n2tGa0SAzAwkQz8UhBn9omYg7c_A9Q8eYwbOLzSq8QUcH6adXME80c7ychmHsy4T8wXRhKExbSThs37Rgq38Z6mkodqYxxdGJw4xoiR3yPij2bXwT6Knes6nXEWYnhPosiLxOhzIIH7-LRPRFVd3aad0cm9TRkNzkEyZ4j2QPtNsKur80sJ0qrEFp-unjoyg59GMNF8yatt8d1hgNgnWIMSuzwRq4U4Da2Q7QMKadhArqNY1mDZJl3duS8No57RMPYipq2y8DVEqKzE2ie-jNs1fmB67hqQ';

        IdToken.set({
          issuer: 'oidc',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });
      });

      it('should throw exception', function () {
        expect(function(){ IdToken.verifyIdTokenInfo(invalidIdToken) }).toThrowError(/Invalid issuer/);
      });

    });

    describe('future issue time', function () {

      beforeEach(function () {
        //Id token issued in the future (20251231235959Z UTC)
        invalidIdToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLWZvbyIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ1MDk5NCwiZXhwIjoxNzY3MjI1NTk5LCJpYXQiOjE3NjcyMjU1OTksImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.d7NrttJitzksr_wJzfvNQJhKTUa2Lp0YIl3B-FNUROMZ4nEGqW385ZwcIZlv1A2BlwbiozZBZ7rpiHHb3yAyfUToL8JD8hzfVurboc63Vp3qpHEMNzLIuWD4AUcYeuBIGz_gIT2sNeltjqJTPFUNm5FPRIs4O-a5b-13rosxI5UhQ7m6MLCUJ_U7w5Jxl5Dei2MUM3dF9ugI5UC17YFsAqWeAnddT2m9TPQGvTS8G42iuEOKxLIBkqE9SCRhcpRy66DWKNi8yyroLMIM9UOiyh2ODrI2sBn1TVa9b6-XkDGwDZdlbc2AWiGLFD2KeoBFYKV03aHhoWL2J9UFs08O8Q';

        IdToken.set({
          issuer: 'oidc',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });
      });

      it('should throw exception', function () {
        expect(function(){ IdToken.verifyIdTokenInfo(invalidIdToken) }).toThrowError(/issued time is later than current time/);
      });

    });

    describe('expired token', function () {

      beforeEach(function () {
        //Expired id token
        invalidIdToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9' +
            '.eyJpc3MiOiJvaWRjLWZvbyIsInN1YiI6Im9hdXRoLW5nLWNsaWVudCIsIm5iZiI6MTQ0OTQ1MTIxMywiZXhwIjoxNDQ5NDUxMjEzLCJpYXQiOjE0NDk0NTEyMTMsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9' +
            '.PAUYJX7v7xDRAVaIUNME7VxK5j2GFDE19bMaa6I-jFa5Lw5f0WlXBOa2WXYqynPymtC0-UMTdUeZ4V_mA07ubTNKyyyqNelr-kpGvM3NzIZpHokEibQVF3JeK1pH_pqnC_MYHePZMiejCkSSPMvC1_lvPOMiMfEhqWvqh58aw7v8q9a9OQYsTlQU_q_rq4mTvDkv9gjU8qKqFInLKIU1TZn4tnslFroW70kvOndz8MHOmXCyQOLbyDW9NHgJXCCCxXwEmo00LjxDHQOSC5uMK9mkix513AqZ8Gaj2QB7-4m6rCK23TiffGgIIlLzPq2RPSBbHGv-K5S_lR_Qh8STGA';

        IdToken.set({
          issuer: 'oidc',
          clientId: 'oauth-ng-client',
          pubKey: publicKeyString
        });
      });

      it('should throw exception', function () {
        expect(function(){ IdToken.verifyIdTokenInfo(invalidIdToken) }).toThrowError(/ID Token expired/);
      });

    });
  });

  describe('WSO2 RSAwithSHA256 testing', function () {

      it('should verify the signature', function () {
        var wsoIdToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJTSEEyNTZ3aXRoUlNBIiwieDV0IjoiTkdVMk1EZGpNV1k1WXpSaU1tVXlZamRtTXprelpHTXlORFV3TVRVMk5Ua3pPREF3TnpBd1pRIn0" +
            ".eyJpc3MiOiJodHRwOi8vd3NvMi5vcmcvZ2F0ZXdheSIsImV4cCI6MTQ0OTE5ODE2MTUwMSwiaHR0cDovL3dzbzIub3JnL2dhdGV3YXkvc3Vic2NyaWJlciI6ImFkbWluIiwiaHR0cDovL3dzbzIub3JnL2dhdGV3YXkvYXBwbGljYXRpb25uYW1lIjoiY2FyZSIsImh0dHA6Ly93c28yLm9yZy9nYXRld2F5L2VuZHVzZXIiOiJhZG1pbkBjYXJlLmNvbSIsICJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2VtYWlsYWRkcmVzcyI6ImFkbWluQGNhcmUuY29tIiwgImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvZ2l2ZW5uYW1lIjoiYWRtaW4iLCAiaHR0cDovL3dzbzIub3JnL2NsYWltcy9sYXN0bmFtZSI6ImFkbWluIiwgImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvcm9sZSI6ImFkbWluLEludGVybmFsL2NhcmUsSW50ZXJuYWwvYWRtaW5fRGVmYXVsdEFwcGxpY2F0aW9uX1BST0RVQ1RJT04sSW50ZXJuYWwvYWRtaW5fQ2FyZV9QUk9EVUNUSU9OLEludGVybmFsL2V2ZXJ5b25lIn0" +
            ".dSTrkA4tQ53iP-q7bd77Es21d-OsqG0uWqYp02yGlnHVBPJfwTi9qW4NitjH260WWIGnOwGKYiiuE2Zw6YZ_zxc_DJiIf3UczQT7tFfLvusQL69b1szppSwHTFuTMojx9lF_tNEnl0f-lLW3IRDTK9I_4NGlJbXTgx-bkAiLZKo";

        var pem = "-----BEGIN CERTIFICATE-----\n"
            + "MIICBTCCAW6gAwIBAgIEaq8KvDANBgkqhkiG9w0BAQQFADBHMREwDwYDVQQDEwhj\n"
            + "YXJlLmNvbTENMAsGA1UECxMETm9uZTEUMBIGA1UEChMLTm9uZSBMPU5vbmUxDTAL\n"
            + "BgNVBAYTBE5vbmUwHhcNMTUxMDA0MDAyNjMyWhcNMjUxMDMxMDAyNjMyWjBHMREw\n"
            + "DwYDVQQDEwhjYXJlLmNvbTENMAsGA1UECxMETm9uZTEUMBIGA1UEChMLTm9uZSBM\n"
            + "PU5vbmUxDTALBgNVBAYTBE5vbmUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n"
            + "AIBzx6MggSa+WXPOMjAisj/BqARDQgE/PPem3GkfoderDBKARdr4ImcNAIWilN65\n"
            + "vi0ePLS/L6pCXXXDKsmNRvrbkDktrRtQ+iOBB0IKYvILXovcEGTpSFClGnKKULP4\n"
            + "8rSu5pH1pJGQpBa+p5RYZhdo5+f5N+2PG7SSTeSlQhkHAgMBAAEwDQYJKoZIhvcN\n"
            + "AQEEBQADgYEAMBbuVdHSEc3YV59XKJWWJ3rA+ZiuPBNAeacRrn2OJf1+TSZpMZ20\n"
            + "Dh1IeF3cL+xlSi0xKOIKaYCFTlEy61ylOr7gL9Lj2rmsIuKi8joD/6pz/mkpILrv\n"
            + "dIRWPx/3n8OoV75UBe2KtU5Br2eQbr3/TLiUSyZuWnjcd/oQ1gX1BlA=\n"
            + "-----END CERTIFICATE-----\n";

        var x509 = new X509();
        x509.readCertPEM(pem);

        //header.body
        var sMsg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJTSEEyNTZ3aXRoUlNBIiwieDV0IjoiTkdVMk1EZGpNV1k1WXpSaU1tVXlZamRtTXprelpHTXlORFV3TVRVMk5Ua3pPREF3TnpBd1pRIn0.eyJpc3MiOiJodHRwOi8vd3NvMi5vcmcvZ2F0ZXdheSIsImV4cCI6MTQ0OTE5ODE2MTUwMSwiaHR0cDovL3dzbzIub3JnL2dhdGV3YXkvc3Vic2NyaWJlciI6ImFkbWluIiwiaHR0cDovL3dzbzIub3JnL2dhdGV3YXkvYXBwbGljYXRpb25uYW1lIjoiY2FyZSIsImh0dHA6Ly93c28yLm9yZy9nYXRld2F5L2VuZHVzZXIiOiJhZG1pbkBjYXJlLmNvbSIsICJodHRwOi8vd3NvMi5vcmcvY2xhaW1zL2VtYWlsYWRkcmVzcyI6ImFkbWluQGNhcmUuY29tIiwgImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvZ2l2ZW5uYW1lIjoiYWRtaW4iLCAiaHR0cDovL3dzbzIub3JnL2NsYWltcy9sYXN0bmFtZSI6ImFkbWluIiwgImh0dHA6Ly93c28yLm9yZy9jbGFpbXMvcm9sZSI6ImFkbWluLEludGVybmFsL2NhcmUsSW50ZXJuYWwvYWRtaW5fRGVmYXVsdEFwcGxpY2F0aW9uX1BST0RVQ1RJT04sSW50ZXJuYWwvYWRtaW5fQ2FyZV9QUk9EVUNUSU9OLEludGVybmFsL2V2ZXJ5b25lIn0';
        //hex signature string
        var hSig = '7524eb900e2d439de23feabb6ddefb12cdb577e3aca86d2e5aa629d36c869671d504f25fc138bda96e0d8ad8c7dbad165881a73b018a6228ae136670e9867fcf173f0c98887f751ccd04fbb457cbbeeb102faf5bd6cce9a52c074c5b933288f1f6517fb4d1279747fe94b5b72110d32bd23fe0d1a525b5d3831f9b90088b64aa';

        var isValid = x509.subjectPublicKeyRSA.verifyString(sMsg, hSig);
        expect(isValid).toEqual(true);

        expect(IdToken.verifyIdTokenSignatureByX509(wsoIdToken, pem)).toEqual(true);

      });
  });


});
