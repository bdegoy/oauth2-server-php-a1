<?php

namespace OAuth2\OpenID\ResponseType;

class CodeIdToken implements CodeIdTokenInterface
{
    /**
     * @var AuthorizationCodeInterface
     */
    protected $authCode;

    /**
     * @var IdTokenInterface
     */
    protected $idToken;

    /**
     * @param AuthorizationCodeInterface $authCode
     * @param IdTokenInterface           $idToken
     */
    public function __construct(AuthorizationCodeInterface $authCode, IdTokenInterface $idToken)
    {
        $this->authCode = $authCode;
        $this->idToken = $idToken;
    }

    /**
     * @param array $params
     * @param mixed $user_id
     * @return mixed
     */
    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->authCode->getAuthorizeResponse($params, $user_id);
        $this->idToken->set_authcode($result[1]['query']['code']);  //[dnc140] needed to set at_hash in JWT
        $resultIdToken = $this->idToken->getAuthorizeResponse($params, $user_id);
        
        /**
        * [dnc139] Hybrid flow require params to be returned in the URL fragment
        * @see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.5
        */
        $result[1]['fragment']['code']  = $result[1]['query']['code'];
        $result[1]['fragment']['state']  = $result[1]['query']['state'];
        unset ($result[1]['query']);
        $result[1]['fragment']['id_token']  = $resultIdToken[1]['fragment']['id_token']; 

        return $result;
    }
}
