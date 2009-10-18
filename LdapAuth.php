<?php

/**
 * LdapAuth.php
 * Authenticate user from OpenLDAP.
 * @author Filipp Lepalaan <filipp@mac.com>
 * 15.10.2009
 */

class LdapAuth
{
  /**
   * @param $ldap_server [string] Address of LDAP server
   * @param $bas_dn [string] search base for the LDAP search (eg. dc=server,dc=example,dc=com)
   */
  public function __construct($ldap_server, $base_dn)
  {
    $this->ds = ldap_connect($ldap_server) or exit("LDAP connection failed");
    $this->base_dn = $base_dn;
    return $this;
  }
  
  /**
   * @return false on error, the user array otherwise
   * @param $username [string] user name
   * @param $password [string] clear text password
   */
  public function auth($username, $password)
  {
    if (empty($username) || empty($password)) {
      print("Sorry, empty names and passwords are not allowed");
      return false;
    }
    
    $out = array();
	  $groups = array();
	  
	  if (!function_exists("ldap_connect")) {
      print("Sorry, but your PHP lacks LDAP support.\n");
      return false;
	  }
	
	  ldap_set_option($this->ds, LDAP_OPT_PROTOCOL_VERSION, 3);
	  ldap_set_option($this->ds, LDAP_OPT_NETWORK_TIMEOUT, 10);
	
	  $base_dn = $this->base_dn;
	  $result = ldap_search($this->ds, "cn=users,{$base_dn}", "uid={$username}",
	    array("cn", "uid", "mail", "description")
	    );
	
  	if (!$result) {
		  printf("LDAP connection failed: %s\n", ldap_error($this->ds));
  		return false;
  	}
	
  	/* Connected to server, find user DN */
  	$info = ldap_get_entries($this->ds, $result);
  	$user = $info[0];
  	$user_dn = $user['dn'];
  	$user_id  = $user['uid'][0];
  	
  	/* Remove the count from the list of addresses */
	  array_shift($user['mail']);
	  array_shift($user['description']);
	  
	  /* Authenticate */
	  $r = ldap_bind($this->ds, $user_dn, $password);
	  
  	if (!$r) {
  		$ec = ldap_errno($this->ds);
  		// 53 = "Server is unwilling" ie "correct user but bad pw"
  		$error = ($ec == 53) ? "Incorrect user name or password\n" : ldap_error($this->ds);
      print($error);
      return false;
  	}
  	
	  /* Fetch all groups the user belongs to */
	  $result = ldap_search($this->ds, "cn=groups,{$base_dn}", "memberuid={$user_id}", array('cn'));
	  $result = ldap_get_entries($this->ds, $result);
    
	  unset($result['count']); // First is just "count"

  	foreach($result as $g) {
      $groups[] = $g['cn'][0];
  	}
	
  	/* Done - close connection and unbind */
  	ldap_unbind($this->ds);

  	return array(
  	  'id'            => $user_id,
  	  'mail'          => $user['mail'],
  	  'groups'        => $groups,
  	  'fullname'      => $user['cn'][0],
  		'description'   => $user['description']
  	);
	
	  return false;
    
  }

}

?>