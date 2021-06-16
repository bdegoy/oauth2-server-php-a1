<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\ResponseType\ResponseTypeInterface;

interface IdTokenInterface extends ResponseTypeInterface
{
    /**
     * Create the id token.
     *
     * If Authorization Code Flow is used, the id_token is generated when the
     * authorization code is issued, and later returned from the token endpoint
     * together with the access_token.
     * 
     * If the Implicit/Hybrid Flow is used, the token and id_token are generated and
     * returned together.
     * @see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.5
     *
     * @param string $client_id        - The client id.
     * @param mixed  $userInfo         - User info
     * @param string $nonce            - OPTIONAL The nonce.
     * @param string $userClaims       - OPTIONAL Claims about the user.
     * 
     * [dnc140] Note $access_token and $authcode are now ID Token properties. 
     * Theese should be set as needed @see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11

     * @internal param string $user_id - The user id.
     * @return string The ID Token represented as a JSON Web Token (JWT).
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     */
    public function createIdToken($client_id, $userInfo, $nonce = null, $userClaims = null);   //[dnc140]
}
