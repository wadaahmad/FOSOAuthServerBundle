<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Security\Authentication\Provider;

use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use OAuth2\OAuth2;
use OAuth2\OAuth2AuthenticateException;
use OAuth2\OAuth2ServerException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use App\Infrastructure\Symfony\Utils\Connection\ConferenceConnectionHandler;
use App\Infrastructure\Symfony\Utils\Connection\ConferenceDatabaseConnection;
use App\Infrastructure\Symfony\Utils\SiteManager;
use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Symfony\Component\Routing\RouterInterface;
use Doctrine\Persistence\ManagerRegistry;
/**
 * OAuthProvider class.
 *
 * @author  Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuthProvider implements AuthenticationProviderInterface
{
    const CENTRALS = array('as1','as2','as3'); 
    /**
     * @var UserProviderInterface
     */
    protected $userProvider;
    /**
     * @var OAuth2
     */
    protected $serverService;
    /**
     * @var UserCheckerInterface
     */
    protected $userChecker;

    /**
     * @param UserProviderInterface $userProvider  the user provider
     * @param OAuth2                $serverService the OAuth2 server service
     * @param UserCheckerInterface  $userChecker   The Symfony User Checker for Pre and Post auth checks
     */
    public function __construct(UserProviderInterface $userProvider, OAuth2 $serverService, UserCheckerInterface $userChecker)
    {
        $this->userProvider = $userProvider;
        $this->serverService = $serverService;
        $this->userChecker = $userChecker;
        
    }

    /**
     * @param OAuthToken&TokenInterface $token
     *
     * @return OAuthToken|null
     */
    public function authenticate(TokenInterface $token)
    {
        $request=new RequestStack();
        /*
        
        
        ManagerRegistry::getManager();
        //$route = new Router;
        //dd($this);
        $conn = new ConferenceDatabaseConnection(Doctrine\Persistence\ManagerRegistry::class);
        foreach (CENTRALS as $dc) {
            //connect to datacenter(lakeconference)
            $db = $conn->switchDataCenter($dc);
            #get conference db
            $db = $conn->getConferenceInfo($conferenceId);

            if (null == $db || $db->getDb() == "") {
                continue;
            }

            // connect to local database
            
            $db = $conn->switchDb($conferenceId);
          
            break;
        }
        */
        if (!$this->supports($token)) {
            // note: since strict types in PHP 7, return; and return null; are not the same
            // Symfony's interface says to "never return null", but return; is still technically null
            // PHPStan treats return; as return (void);
            return null;
        }

        try {
            $tokenString = $token->getToken();

            // TODO: this is nasty, create a proper interface here
            /** @var OAuthToken&TokenInterface&\OAuth2\Model\IOAuth2AccessToken $accessToken */
            $accessToken = $this->serverService->verifyAccessToken($tokenString);
            //dd($accessToken);
            $scope = $accessToken->getScope();
            $user = $accessToken->getUser();
            $conference = $accessToken->getConferenceId();
            $this->userProvider->conference=$conference;
            $all['conference']=$accessToken->getConferenceId();
            $request->replace($all);
            //$conn = new ConferenceConnectionHandler(new SiteManager($request,$route), new ConferenceDatabaseConnection);
            //$conn->handleConnection($conference);
            //dd($accessToken);
            if (null !== $user) {
                try {
                    $this->userChecker->checkPreAuth($user);
                } catch (AccountStatusException $e) {
                    //dd($e);
                    throw new OAuth2AuthenticateException(Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM), 'access_denied', $e->getMessage());
                }

                $token->setUser($user);
            }
            //dd($user);
            $roles = (null !== $user) ? $user->getRoles() : [];

            if (!empty($scope)) {
                foreach (explode(' ', $scope) as $role) {
                    $roles[] = 'ROLE_'.mb_strtoupper($role);
                }
            }

            $roles = array_unique($roles, SORT_REGULAR);
            //dd($roles);
            $token = new OAuthToken($roles);
            $token->setAuthenticated(true);
            $token->setToken($tokenString);

            if (null !== $user) {
                try {
                    $this->userChecker->checkPostAuth($user);
                } catch (AccountStatusException $e) {
                    throw new OAuth2AuthenticateException(Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM), 'access_denied', $e->getMessage());
                }

                $token->setUser($user);
            }

            return $token;
        } catch (OAuth2ServerException $e) {
            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }

        throw new AuthenticationException('OAuth2 authentication failed');
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken;
    }
}
