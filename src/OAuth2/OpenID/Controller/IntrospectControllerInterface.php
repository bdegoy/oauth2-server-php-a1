<?php
/**
* Introspection
* Author B.Degoy 2019/06/21...
*/

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
*  This controller is called when a client claims for token verification.
*
* @code
*     $response = new OAuth2\Response();
*     $IntrospectController->handleIntrospectRequest(
*         OAuth2\Request::createFromGlobals(),
*         $response
*     );
*     $response->send();
* @endcode
*/
interface IntrospectControllerInterface
{
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
    public function handleIntrospectRequest(RequestInterface $request, ResponseInterface $response,  string $scope = null);

    
    /**
    * Verify the introspect request
    *
    * @param RequestInterface  $request
    * @param ResponseInterface $response
    * @param string $scope
    * @param string $enforceclaims
    * @return bool
    */
    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response,  string $scope = null);

    
    /** @see rfc7662 Section 2.1. Authenticate client.
    * The rfc states that the goal of client authentication is "To prevent token scanning attacks ..."
    * Scanning attacks might be better mitigated in some othe ways, particularly at the network level.
    * On an other hand, giving an unknown client information about validity of the token is not a high security concern.
    * So we may skip client authentication at this level.
    * If not defined, default to true.

    * @param bool $val
    */
    public function setNeedsClientAuthentication( bool $val);
    
   
   /** @see rfc7662 section 2.3.
    * Decode a JWT, validate its signature and return the payload if the JWT is properly formed and authorized.
    * A JWT being out of time limits ( active = false) is not considered an introspection error.
    * 'active' claim = true/false indicates token validity. 
    * 
    * @param String undecoded JWT
    * @param RequestInterface $request
    * @param ResponseInterface $response
    * @param String enforceclaim : space delimited list of claims that should be present 
    * @return mixed : array of decoded payload or null in case of error.
    
    */
    public function validate_jwt( String $undecodedJWT, RequestInterface $request, ResponseInterface $response, String $enforcedclaims = null  );
    
}
