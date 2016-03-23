<?php

namespace ShineUnited\Silex\GoogleAuth;

use ShineUnited\Silex\Common\Application as BaseApplication;

use Gigablah\Silex\OAuth\OAuthServiceProvider;
use Silex\Application\SecurityTrait;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Symfony\Component\HttpFoundation\Session\Storage\Handler\PdoSessionHandler;


class Application extends BaseApplication {
	use SecurityTrait;

	protected function initialize() {
		// setup route class
		$this['route_class'] = 'ShineUnited\\Silex\\GoogleAuth\\Route';

		parent::initialize();

		$this->initializeOAuthService();
		$this->initializeSecurityService();
		$this->initializeSessionService();
	}

	private function initializeOAuthService() {
		$this->register(new OAuthServiceProvider());

		$this['oauth.services'] = $this->share(function() {
			if(!isset($_ENV['GOOGLE_OAUTH_KEY']) || !isset($_ENV['GOOGLE_OAUTH_SECRET'])) {
				throw new \InvalidArgumentException('Identifier "oauth.services" is not defined.');
			}

			return [
				'google' => [
					'key'           => $_ENV['GOOGLE_OAUTH_KEY'],
					'secret'        => $_ENV['GOOGLE_OAUTH_SECRET'],
					'scope'         => [
						'https://www.googleapis.com/auth/userinfo.email',
						'https://www.googleapis.com/auth/userinfo.profile'
					],
					'user_endpoint' => 'https://www.googleapis.com/oauth2/v1/userinfo'
				]
			];
		});
	}

	private function initializeSecurityService() {
		$this->register(new SecurityServiceProvider());

		$this['security.default_roles'] = [
			'ROLE_GUEST'
		];

		$this['security.firewalls'] = $this->share(function() {
			$firewalls = [
				'default' => [
					'pattern'   => '^/',
					'anonymous' => true,
					'oauth'     => [
						'failure_path' => '/',
						'with_csrf'    => true
					],
					'logout'    => [
						'logout_path'  => '/logout',
						'with_csrf'    => true
					],
					'users'     => new UserProvider($this['db'], $this['security.default_roles'])
				]
			];

			$this['security.access_rules'] = [
				['^/auth', 'ROLE_USER']
			];

			return $firewalls;
		});

		$app['db.schema'] = $this->share($this->extend('db.schema', function($schema) {
			$users = $schema->createTable('users');
			$users->addColumn('email', 'string', ['length' => 255]);
			$users->addColumn('roles', 'text');
			$users->addColumn('modified', 'datetime');
			$users->addColumn('created', 'datetime');
			$users->setPrimaryKey(['email']);

			return $schema;
		}));
	}

	private function initializeSessionService() {
		$this->register(new SessionServiceProvider());

		$this['session.storage.handler'] = $this->share(function() {
			return new PdoSessionHandler(
				$this['db']->getWrappedConnection(),
				array(
					'db_table'        => 'sessions',
					'db_id_col'       => 'id',
					'db_data_col'     => 'data',
					'db_lifetime_col' => 'lifetime',
					'db_time_col'     => 'time'
				),
				$this['session.storage.options']
			);
		});

		$app['db.schema'] = $this->share($this->extend('db.schema', function($schema) {
			$sessions = $schema->createTable('sessions');
			$sessions->addColumn('id', 'string', ['length' => 255]);
			$sessions->addColumn('data', 'text');
			$sessions->addColumn('lifetime', 'integer');
			$sessions->addColumn('time', 'integer', ['unsigned' => true]);
			$sessions->setPrimaryKey(['id']);

			return $schema;
		}));
	}
}
