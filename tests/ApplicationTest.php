<?php

namespace ShineUnited\Silex\GoogleAuth\Tests;

use ShineUnited\Silex\GoogleAuth\Application;


class ApplicationTest extends \PHPUnit_Framework_TestCase {

	public function testOAuthMissingServices() {
		$app = new Application();

		$this->setExpectedException('InvalidArgumentException');
		$app['oauth.services'];
	}

	public function testOAuthEnvConfig() {
		$key = 'OAUTHKEY';
		$secret = 'OAUTHSECRET';

		$_ENV['GOOGLE_OAUTH_KEY'] = $key;
		$_ENV['GOOGLE_OAUTH_SECRET'] = $secret;

		$app = new Application();

		$this->assertEquals($key, $app['oauth.services']['google']['key']);
		$this->assertEquals($secret, $app['oauth.services']['google']['secret']);
	}
}
