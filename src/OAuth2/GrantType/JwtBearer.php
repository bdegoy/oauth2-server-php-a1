<?php

namespace OAuth2\GrantType;

use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * The JWT bearer authorization grant implements JWT (JSON Web Tokens) as a grant type per the IETF draft.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-4
 *
 * @author F21
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class JwtBearer implements GrantTypeInterface, ClientAssertionTypeInterface
{
    private $jwt;

    protected $storage;
    protected $audience;
    protected $jwtUtil;
    protected $allowedAlgorithms;

    /**
     * Creates an instance of the JWT bearer grant type.
     *
     * @param JwtBearerInterface      $storage  - A valid storage interface that implements storage hooks for the JWT
     *                                            bearer grant type.
     * @param string                  $audience - The audience to validate the token against. This is usually the full
     *                                            URI of the OAuth token requests endpoint.
     * @param EncryptionInterface|JWT $jwtUtil  - OPTONAL The class used to decode, encode and verify JWTs.
     * @param array                   $config
     */
    public function __construct(JwtBearerInterface $storage, $audience, EncryptionInterface $jwtUtil = null, array $config = array())
    {
        $this->storage = $storage;
        $this->audience = $audience;

        if (is_null($jwtUtil)) {
            $jwtUtil = new Jwt();
        }

        $this->config = array_merge(array(
            'allowed_algorithms' => array('RS256', 'RS384', 'RS512')
        ), $config);

        $this->jwtUtil = $jwtUtil;

        $this->allowedAlgorithms = $this->config['allowed_algorithms'];
    }

    /**
     * Returns the grant_type get parameter to identify the grant type request as JWT bearer authorization grant.
     *
     * @return string - The string identifier for grant_type.
     *
     * @see GrantTypeInterface::getQueryStringIdentifier()
     */
    public function getQueryStringIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * Validates the data from the decoded JWT.
     *
     * @param RequestInterface  $request
     * @param ResponseInterface $response
     * @return bool|mixed|null TRUE if the JWT request is valid and can be decoded. Otherwise, FALSE is returned.@see GrantTypeInterface::getTokenData()
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request("assertion")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return null;
        }

        $undecodedJWT = $request->request('assertion');

        //[dnc128] use the validate_jwt method of introspect controller.
        $introspectController = $this->server->getIntrospectController();
        $this->jwt = $introspectController->validate_jwt($undecodedJWT, $request, $response);

        return true;     // 'active' claim may be false, always check its value.
    }

    /**
     * Get client id
     *
     * @return mixed
     */
    public function getClientId()
    {
        return $this->jwt['iss'];
    }

    /**
     * Get user id
     *
     * @return mixed
     */
    public function getUserId()
    {
        return $this->jwt['sub'];
    }

    /**
     * Get scope
     *
     * @return null
     */
    public function getScope()
    {
        return null;
    }

    /**
     * Creates an access token that is NOT associated with a refresh token.
     * If a subject (sub) the name of the user/account we are accessing data on behalf of.
     *
     * @see GrantTypeInterface::createAccessToken()
     *
     * @param AccessTokenInterface $accessToken
     * @param mixed                $client_id   - client identifier related to the access token.
     * @param mixed                $user_id     - user id associated with the access token
     * @param string               $scope       - scopes to be stored in space-separated string.
     * @return array
     */
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope, $acr)   //[dnc91g]
    {
        $includeRefreshToken = false;

        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken, $acr);    //[dnc91g]
    }
}
