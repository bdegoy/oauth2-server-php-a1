oauth2-server-php version A1 pour OAuthSD
=========================================

View the [bshaffer documentation](https://bshaffer.github.io/oauth2-server-php-docs/)

This version for OAuthSD includes some modifications and additions to bshaffer's oauth2-server-php (https://github.com/bshaffer/oauth2-server-php).
Most are small, but some are noticable :
- kid claim added in JWT payload, see : https://oa.dnc.global/web/-API-OpenID-Connect-Points-d-extremite-.html#apiopenidconnectpointdextremitedinformationssurlesclefskeysendpoint
- acr claim added in JWT payload, see : https://oa.dnc.global/web/-Identifier-l-utilisateur-final-.html#acr_valuesrequestedauthenticationcontextclassreference
- jku and jkw added in JWT Header,
- ability to add extra payload trough callable function extrapayload(), see : https://oa.dnc.global/web/-Json-Web-Token-JWT-40-.html#addadditionalclaimstothejwttoken
- JWE validation, see : https://oa.dnc.global/web/-JSON-Web-Token-JWT-JWS-.html#jwejsonwebencryption
- Introspection, see : https://oa.dnc.global/web/-API-OpenID-Connect-Points-d-extremite-.html#apiopenidconnectintrospection

Some of these mods were needed to allow OAuthSD reaching 100% Compliance with OpenID Connect Provider Certification (openid.net), Configuration Basic OP. 
    See : https://oa.dnc.global/web/-Tests-et-certification-.html#oauthsdverslacertificationopenidr
