<?php
namespace DOMJudgeBundle\Security;

use DOMJudgeBundle\Security\Authentication\Token\AlternateLoginToken;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface as Container;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;

class DOMJudgeBasicAuthenticator extends AbstractGuardAuthenticator
{
    private $csrfTokenManager;
    private $security;
    private $encoder;
    private $container;

    public function __construct(CsrfTokenManagerInterface $csrfTokenManager, Container $container, Security $security, UserPasswordEncoderInterface $encoder) {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->container = $container;
        $this->security = $security;
        $this->encoder = $encoder;
    }
    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        // if there is already an authenticated user (likely due to the session)
        // then return null and skip authentication: there is no need.
        if ($this->security->getUser()) {
            return false;
        }

        // This authenticator only supports stateless security endpoints
        $fwmap = $this->container->get('security.firewall.map');
        if ($fwmap->getFirewallConfig($request)->isStateless()) {
          return true;
        }
        return false;
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        return [
            'username'  => $request->headers->get('php-auth-user'),
            'password'  => $request->headers->get('php-auth-pw'),
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if ($credentials['username'] == null) {
          return null;
        }
        return $userProvider->loadUserByUsername($credentials['username']);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return $this->encoder->isPasswordValid($user, $credentials['password']);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return null;
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
