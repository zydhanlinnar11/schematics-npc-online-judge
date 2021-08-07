<?php declare(strict_types=1);

namespace App\Security;
use Exception;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use \Firebase\JWT\JWT;

class SchematicsAuthenticator extends AbstractGuardAuthenticator
{
    private $security;
    private $params;

    public function __construct(
        Security $security,
        ContainerBagInterface $params)
    {
        $this->security = $security;
        $this->params = $params;
    }

    public function getCredentials(Request $request)
    {
        return $request->get('token', '');
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $jwt = (array) JWT::decode($credentials, $this->params->get('jwt_secret'), ['HS256']);
            if(!isset($jwt['exp']) || $jwt['exp'] < time())
                throw new AuthenticationException('Token expired.');
            return $userProvider->loadUserByUsername($jwt['username']);
        } catch (Exception $exception) {
            throw new AuthenticationException($exception->getMessage());
        }
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if($user) {
            return true;
        }
        return false;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // Let user retry sign in again
        return null;
    }

    public function supports(Request $request)
    {
        // if there is already an authenticated user (likely due to the session)
        // then return null and skip authentication: there is no need.
        if ($this->security->getUser()) {
            return false;
        }

        return $request->get('token') != null && $request->getMethod() == 'POST'
            && ($request->get('_route') === 'callback_from_schematics');
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = array(
            'message' => 'Authentication Required'
        );

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}