<?php

namespace ShineUnited\ShootSchedule;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\User;
use Doctrine\DBAL\Connection;


class UserProvider implements UserProviderInterface, OAuthUserProviderInterface {
	private $conn;
	private $defaultRoles;

	public function __construct(Connection $conn, array $defaultRoles = []) {
		$this->conn = $conn;
		$this->defaultRoles = $defaultRoles;
	}

	public function loadUserByUsername($username) {
		$username = strtolower(trim($username));

		$sql = 'SELECT * FROM users WHERE email = ?';
		if(!$record = $this->conn->fetchAssoc($sql, [$username])) {
			// create record
			$user = new User($username, '', $this->defaultRoles);

			return $this->createUser($user);
		}

		return new User(
			$record['email'],
			'',
			unserialize($record['roles'])
		);
	}

	public function refreshUser(UserInterface $user) {
		if(!$user instanceof User) {
			throw new UnsupportedUserException('Instances of "' . get_class($user) . '" are not supported');
		}

		return $this->loadUserByUsername($user->getUsername());
	}

	public function createUser(UserInterface $user) {
		if(!$user instanceof User) {
			throw new UnsupportedUserException('Instances of "' . get_class($user) . '" are not supported');
		}

		$sql = 'INSERT INTO users SET email = ?, roles = ?, modified = NOW(), created = NOW()';
		$values = [
			$user->getUsername(),
			serialize($user->getRoles())
		];

		if(!$this->conn->executeUpdate($sql, $values)) {
			throw new \LogicException('User "' . $user->getUsername() . '" already exists');
		}

		return $this->refreshUser($user);
	}

	public function updateUser(UserInterface $user) {
		if(!$user instanceof User) {
			throw new UnsupportedUserException('Instances of "' . get_class($user) . '" are not supported');
		}

		$sql = 'UPDATE users SET roles = ?, modified = NOW() WHERE email = ?';
		$values = [
			serialize($user->getRoles()),
			$user->getUsername()
		];

		$this->conn->executeUpdate($sql, $values);

		return $this->refreshUser($user);
	}

	public function addUserToRole(UserInterface $user, $role) {
		if(!$user instanceof User) {
			throw new UnsupportedUserException('Instances of "' . get_class($user) . '" are not supported');
		}

		$user = $this->refreshUser($user);

		$email = $user->getUsername();
		$roles = $user->getRoles();

		if(in_array($role, $roles)) {
			// role already added, ignore
			return $user;
		}

		$roles[] = $role;

		$user = new User($email, '', $roles);
		return $this->updateUser($user);
	}

	public function removeUserFromRole(UserInterface $user, $role) {
		if(!$user instanceof User) {
			throw new UnsupportedUserException('Instances of "' . get_class($user) . '" are not supported');
		}

		$user = $this->refreshUser($user);

		$email = $user->getUsername();
		$roles = $user->getRoles();

		if(!in_array($role, $roles)) {
			// role doesn't current exist, ignore
			return $user;
		}

		$roles = array_diff($roles, [$role]);

		$user = new User($email, '', $roles);
		return $this->updateUser($user);
	}

	public function supportsClass($class) {
		if($class === 'Symfony\Component\Security\Core\User\User') {
			return true;
		}

		return false;
	}

	public function loadUserByOAuthCredentials(OAuthTokenInterface $token) {
		return $this->loadUserByUsername($token->getEmail());
	}
}
