<?php
/*
[dnc132] 2021/03/30 : Extend the Resource controller to client authentication with HTTP Basic.
Allow to retreive the authentication method and client_id.
*/

namespace OAuth2\Controller;

use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\Storage\ClientCredentialsInterface; //[dnc132]
use OAuth2\ScopeInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Scope;

/**
* @see ResourceControllerInterface
*/
class ResourceController implements ResourceControllerInterface
{
    /**
    * @var array
    */
    private $token;

    /** [dnc132b]
    * @var string
    */
    private $client_authentication_method;    // null if client authentication not performed (not needed, unknown or failed)

    /** [dnc132b]
    * @var string
    */
    private $client_id = null;     // null if client authentication not performed (not needed, unknown or failed)


    /**
    * @var TokenTypeInterface
    */
    protected $tokenType;

    /**
    * @var AccessTokenInterface
    */
    protected $tokenStorage;

    /** [dnc132]
    * @var ClientCredentialsInterface
    */
    protected $clientCredentialsStorage;

    /**
    * @var array
    */
    protected $config;

    /**
    * @var ScopeInterface
    */
    protected $scopeUtil;

    /**
    * Constructor
    *
    * @param TokenTypeInterface   $tokenType
    * @param AccessTokenInterface $tokenStorage
    * @param ClientCredentialsInterface $clientCredentials      //[dnc132]
    * @param array                $config
    * @param ScopeInterface       $scopeUtil
    */
    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, ClientCredentialsInterface $clientCredentials, $config = array(), ScopeInterface $scopeUtil = null)       //[dnc132]
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;
        $this->clientCredentialsStorage = $clientCredentials;   //[dnc132]

        $this->config = array_merge(array(
            'www_realm' => 'Service',
            ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    /** [dnc132]
    * Verify the resource request
    *
    * @param RequestInterface  $request
    * @param ResponseInterface $response
    * @param null              $scope
    * @return bool
    */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, $scope = null)
    {

        $this->client_authentication_method = null;
        $this->client_id = null;
        $this->token = null;
        
        // Get authorization method, check token first
        $method = null;
        $autheader = $request->headers('AUTHORIZATION');        
        if ( strtolower(substr($autheader, 0, 6)) == 'bearer' ) {
            $method = 'bearer_token';
        } else if ( $request->request('access_token') ) {
            $method = 'token_in_request_body';    
        } else if ($request->query('access_token') ) {
            $method = 'token_in_request_query';      
        }

        if ( !is_null($method) ) {
            
            //// We have a token

            /**
            * Check scope, if provided
            * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
            * @see http://tools.ietf.org/html/rfc6750#section-3.1
            */
            $token = $this->getAccessTokenData($request, $response);
            if (!is_null($token)) {
                if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
                    $response->setError(403, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
                    $response->addHttpHeaders(array(
                        'WWW-Authenticate' => sprintf('%s realm="%s", scope="%s", error="%s", error_description="%s"',
                            $this->tokenType->getTokenType(),
                            $this->config['www_realm'],
                            $scope,
                            $response->getParameter('error'),
                            $response->getParameter('error_description')
                        )
                    ));
                    
                    // insuficient scope
                    return false;
                }
            } else {
                // missing or ill token 
                return false;        
            }

            //[dnc132b] Allow client authentication data retrivial
            $this->client_authentication_method = $method;
            $this->client_id = $token['client_id'];    
            // allow retrieval of the token
            $this->token = $token;
            return true; 

        } else {
            
            //// we may have client credentials

            if ( strtolower(substr($autheader, 0, 5)) == 'basic' ) {
                $method = 'client_secret_basic';
            } else if ( $request->request('client_id') ) {
                $method = 'credentials_in_request_body';   
            }

            if ( !is_null($method) ) {

                //[dnc132] might be HTTP Basic

                /* Nota :php-cgi under Apache needs this rewrite rule in the .htaccess file to pass PHP_AUTH_USER :
                RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]  [QSA,L,skip=100]
                */

                $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_credentials_in_request_body allow_public_clients')));   // ???
                $csbh = New \OAuth2\ClientAssertionType\HttpBasic($this->clientCredentialsStorage, $config);

                if ($csbh->validateRequest($request, $response)) {
                    $this->client_authentication_method = $method;
                    $this->client_id = $csbh->getClientId(); 
                    return true;

                } else {
                    // authentication failed 
                    return false;
                }

            } else {
                // unknown or not accepted method
                return false;
            }      

        } 

        if ( is_null($this->client_authentication_method) ) {
            // unknown or not accepted method

            return false;
        }

    }
    

    /**
    * Get access token data.
    *
    * @param RequestInterface  $request
    * @param ResponseInterface $response
    * @return array|null
    */
    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response)
    {
        // Get the token parameter
        if ($token_param = $this->tokenType->getAccessTokenParameter($request, $response)) {
            // Get the stored token data (from the implementing subclass)
            // Check we have a well formed token
            // Check token expiration (expires is a mandatory paramter)
            if (!$token = $this->tokenStorage->getAccessToken($token_param)) {
                $response->setError(401, 'invalid_token', 'The access token provided is invalid');
            } elseif (!isset($token["expires"]) || !isset($token["client_id"])) {
                $response->setError(401, 'malformed_token', 'Malformed token (missing "expires")');
            } elseif (time() > $token["expires"]) {
                $response->setError(401, 'expired_token', 'The access token provided has expired');  //*****
            } else {
                return $token;
            }
        }

        $authHeader = sprintf('%s realm="%s"', $this->tokenType->getTokenType(), $this->config['www_realm']);

        if ($error = $response->getParameter('error')) {
            $authHeader = sprintf('%s, error="%s"', $authHeader, $error);
            if ($error_description = $response->getParameter('error_description')) {
                $authHeader = sprintf('%s, error_description="%s"', $authHeader, $error_description);
            }
        }

        $response->addHttpHeaders(array('WWW-Authenticate' => $authHeader));

        return null;
    }

    /**
    * convenience method to allow retrieval of the token.
    *
    * @return array
    */
    public function getToken()
    {
        return $this->token;
    }

    /** [dnc132b]
    * convenience method to allow retrieval of client ID.
    *
    * @return mixed string or null
    */
    public function getClientId()
    {
        return $this->client_id;
    }

    /** [dnc132b]
    * convenience method to allow retrieval of client authentication method.
    *
    * @return mixed string or null
    */
    public function getClientAuthenticationMethod()
    {
        return $this->client_authentication_method;
    }
    
    
}
