<?php
/** [dnc128] [dnc132]
* Introspection Controller for OAuthSD
* 
* @see https://datatracker.ietf.org/doc/rfc7662/
* @see https://tools.ietf.org/html/rfc7662
* 
* Posted parameters :
*
* token 
*   REQUIRED. : (TODO :déterminer les types acceptés : JWT et ???)
* audience :
*   OPTIONAL. If token has an audience claim it will be checked against this one.
* token_type_hint : 
*   OPTIONAL. not implemented.
* 
* Authorization of caller :
* According to rfc7662 Section 2.1., "To prevent token scanning attacks, the endpoint MUST require some form of authorization to access this endpoint".
*  
* @author : Bertrand Degoy https://oa.dnc.global
* @author : bschaffer https://github.com/bshaffer/oauth2-server-php
*
* Copyright (c) 2019-2021 - Bertrand Degoy
* Licence : GPL v3.0
*/

namespace OAuth2\OpenID\Controller;

use OAuth2\Scope;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface; //[dnc132]
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\ScopeInterface;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Bearer;

/**
* @see OAuth2\Controller\IntrospectControllerInterface
*/
class IntrospectController extends ResourceController implements IntrospectControllerInterface
{
    /**
    * @var PublicKeyInterface
    */
    protected $publicKeyStorage;

    /**
    * @var EncryptionInterface
    */
    protected $encryptionUtil;

    /** [dnc132c]
    * @var bool
    */
    protected $needs_client_authentication = true;


    /**
    * Constructor
    *
    * @param TokenTypeInterface   $tokenType
    * @param AccessTokenInterface $tokenStorage
    * @param ClientCredentialsInterface $clientCredentials [dnc132] 
    * @param PublicKeyInterface   $publicKeyStorage
    * @param array                $config
    * @param ScopeInterface       $scopeUtil
    */
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, ClientCredentialsInterface $clientCredentials, PublicKeyInterface $publicKeyStorage, $config = array(), ScopeInterface $scopeUtil = null)
    {

        parent::__construct($tokenType, $tokenStorage, $clientCredentials, $config, $scopeUtil);  //[dnc132]

        $this->publicKeyStorage = $publicKeyStorage;

        $this->encryptionUtil = new Jwt();
    }

    /**
    * Handle the introspection request and set response according to token validity.
    * @see rfc7662 section 2.3.
    * The method returns the payload if the token is properly formed and authorized.
    * A token being out of time limits ( active = false) is not considered an introspection error.
    * 'active' claim = true/false indicates token validity. 
    *
    * @param RequestInterface $request
    * @param ResponseInterface $response
    * @param string $scope
    */
    public function handleIntrospectRequest(RequestInterface $request, ResponseInterface $response, string $scope = null)
    {

        // Verify request (include client authentication)
        if (!$this->verifyResourceRequest($request, $response, $scope)) {
            $response->send(); // introspect failed
            die();
        }

        // Get token
        // @see rfc7662 : the parameter name should be 'token', even in the case of an access or refresh token.  
        $token_param = trim($request->request('token'));     

        if (2 === substr_count($token_param, '.')) {

            ////  JWT Token  ////
            $answer = $this->validate_jwt($token_param, $request, $response);  

        } else {

            ////  Access Token  ////  maybe, or something else ;)
            $answer = $this->tokenStorage->getAccessToken($token_param);
            $answer['active'] = (time() < $answer["expires"]);

        }

        // Responds with a JSON object
        $response->addParameters($answer);

    }          


    /**
    * Verify the introspect request.
    *
    * @param RequestInterface  $request
    * @param ResponseInterface $response
    * @param string $scope
    * @string enforceclaims
    * @return boolean true/false
    */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, $scope = null)
    {
        //  @see rfc7662 Section 2.1. The request method must be POST.
        if (strtolower($request->server('REQUEST_METHOD')) !== 'post') {
            $response->setError(405, 'invalid_request', 'The request method must be POST for introspection', '#section-2.1');   // ??? section
            $response->addHttpHeaders(array('Allow' => 'POST, OPTIONS'));

            return false;
        }

        if ( empty(trim($request->request('token'))) ) {
            $response->setError(400, 'invalid_request', 'Missing token parameter', '#section-2.1');   // ??? section

            return false;
        }

        if ( $this->needs_client_authentication ) {  // Client authentication might have been processed before. @see https://oa.dnc.global/web/-API-OpenID-Connect-Points-d-extremite-.html#apiopenidconnectintrospection

            // Authenticate the client.
            // Do not confuse with the validation of the token which is the object of this introspection !
            return parent::verifyResourceRequest($request, $response);


        } else return true;

    }

    //[dnc132c]
    public function setNeedsClientAuthentication( bool $val ) 
    {
        $this->needs_client_authentication = (bool)$val;
    } 


    /**
    * Decode a JWT, validate its signature and return JWT payload if and set response according to JWT validity.
    * @see rfc7662 section 2.3.
    * The method returns the payload if the JWT is properly formed and authorized.
    * A JWT being out of time limits ( active = false) is not considered an introspection error.
    * 'active' claim = true/false indicates token validity. 
    * 
    * @param String undecoded JWT
    * @param RequestInterface $request
    * @param ResponseInterface $response
    * @param String enforceclaim : space delimited list of claims that should be present 
    * @return mixed : array of decoded payload or null in case of error. 
    */

    //TODO: it would be better placed in the IdToken class.

    public function validate_jwt( String $undecodedJWT, RequestInterface $request, ResponseInterface $response, String $enforcedclaims = null  )
    {
        
        $jwt = $this->encryptionUtil->decode($undecodedJWT, null, false);

        // Verify the JWT
        if (!$jwt) {
            $response->setError(400, 'invalid_request', "JWT is malformed");

            return null;
        }
        
        if ( is_null($enforcedclaims) ) $enforcedclaims = \OAuth2\OpenID\ResponseType\IdToken::ENFORCEDCLAIMS; 

        if (empty(trim($jwt['sub'])) AND !is_null($enforcedclaims) AND strpos($enforcedclaims, 'sub') !== false ) {
            $response->setError(400, 'invalid_grant', "No subject (sub) provided");

            return null;
        }

        if (empty(trim($jwt['iss'])) AND !is_null($enforcedclaims) AND strpos($enforcedclaims, 'iss') !== false ) {
            $response->setError(400, 'invalid_grant', "No issuer (iss) provided");

            return null;
        }

        if (empty(trim($jwt['exp'])) AND !is_null($enforcedclaims) AND strpos($enforcedclaims, 'exp') !== false ) {
            $response->setError(400, 'invalid_grant', "Expiration (exp) time must be present");

            return null;
        }

        if (empty(trim($jwt['nbf'])) AND !is_null($enforcedclaims) AND strpos($enforcedclaims, 'nbf') !== false ) {
            $response->setError(400, 'invalid_grant', "Not before (nbf) time must be present");

            return null;
        }

        if (empty(trim($jwt['aud'])) AND !is_null($enforcedclaims) AND strpos($enforcedclaims, 'aud') !== false ) {
            $response->setError(400, 'invalid_grant', "Not before (nbf) time must be present");

            return null;
        }

        // is the JWT in the time limits ? @see rfc7662 Section 4.
        $is_active = true;
        // Check expiration
        if (ctype_digit($jwt['exp'])) {
            if ($jwt['exp'] <= time()) {
                $is_active = false;
            }
        } else {
            $response->setError(400, 'invalid_grant', "Expiration (exp) time must be a unix time stamp");

            return null;
        }
        // Check the not before time
        if ($notBefore = $jwt['nbf']) {
            if (ctype_digit($notBefore)) {
                if ($notBefore > time()) {
                    $is_active = false;
                }
            } else {
                $response->setError(400, 'invalid_grant', "Not Before (nbf) time must be a unix time stamp");

                return null;
            }
        }

        // Check the audience if required to match
        // @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-4.1.3
        $audience = $request->request('audience', $request->query('audience'));
        if ( isset($jwt['aud']) && !is_null($audience) ) {  
            // Audience may be an array or a space delimited list of StringOrURI values.
            if ( is_array($audience) ) $audience = implode(' ', $audience); 
            if ( strpos($jwt['aud'], $audience) !== false )  {
                $response->setError(400, 'invalid_grant', "Invalid audience (aud)");

                return null;
            }
        }

        // Check the jti (nonce)
        // @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-4.1.7
        if (isset($jwt['jti'])) {
            $jti = $this->storage->getJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);

            //Reject if jti is used and jwt is still valid (exp parameter has not expired).
            if ($jti && $jti['expires'] > time()) {
                $response->setError(400, 'invalid_grant', "JSON Token Identifier (jti) has already been used");

                return null;
            } else {
                $this->storage->setJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);
            }
        }

        // Get client and its public key
        // @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06#section-4.1.1
        // Note that we disregard the 'alg' claim to avoid vulnerability, @see https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html
        $client_id  = isset($jwt['aud']) ? $jwt['aud'] : null;     // Use global ("server") public key if client not defined
        $public_key = $this->publicKeyStorage->getPublicKey($client_id);
        $algorithm  = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);
        if ( !is_null($public_key) ) {
            // verify JWT signature
            if ( false === $this->encryptionUtil->decode($undecodedJWT, $public_key, array($algorithm)) ) {
                $response->setError(401, 'invalid_token', 'JWT failed signature verification');

                return null;
            }
        } else {
            // Either we have a null client with no global key, or the client is invalid (has no key).  
            $response->setError(401, 'unauthorized_client', 'Invalid or undefined client');

            return null;
        }

        // @see rfc7662 section 2.2.
        $answer = array (
            'active' => $is_active,        
        );
        $answer = array_merge($jwt, $answer);

        /**
        * If we got here, the JWT is properly formed and authorized. 
        * @see rfc7662 section 2.3.
        * A JWT being out of time limits ( active = false) is not considered an introspection error.
        * $answer['active'] = true/false indicates token validity.
        */

        return $answer;         
    }    

}
