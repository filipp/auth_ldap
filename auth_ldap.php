<?php

/**
 * auth_ldap.php
 * @version 18.10.2009
 * @author Filipp Lepalaan <filipp@mac.com>
 */

$ldap_server = "example.com";
$ldap_basedn = "dc=server,dc=example,dc=com";


/* That's all you should have to change */

require "LdapAuth.php";

$la = new LdapAuth($ldap_server, $ldap_basedn);
$ldap_user = $la->auth($form_username, $form_password);

/* User found in LDAP */
if ($ldap_user != false)
{ 
  $sql = sprintf("SELECT id FROM `users` WHERE username = '%s'", $forum_db->escape($form_username));
  $row = $forum_db->query($sql)->fetch_row();
  
  if (!empty($row)) {
    /* LDAP password has priority */
    $sql = sprintf("UPDATE `users` SET password = '%s' WHERE id = %d", $forum_db->escape($password_hash), $row[0]['id']);
    $forum_db->query($sql);
  }
  else {
    /* Valid LDAP user not in PunBB, so let's add them */
    $initial_group_id = ($forum_config['o_regs_verify'] == '0') ? $forum_config['o_default_user_group'] : FORUM_UNVERIFIED;
    $salt = random_key(12);
    $password_hash = forum_hash($password1, $salt);
    
    /* Insert the new user into the database. Shamelessly ripped from register.php */
  	$user_info = array(
  		'username'			=> $ldap_user['id'],
  		'group_id'			=> $initial_group_id,
  		'salt'					=> $salt,
  		'password'			=> $password1,
  		'password_hash'	=> $password_hash,
  		'email'					=> $ldap_user['mail'][0],
  		'email_setting'	=> $forum_config['o_default_email_setting'],
  		'timezone'			=> $_POST['timezone'],
  		'dst'					  => isset($_POST['dst']) ? '1' : '0',
  		'language'			=> $language,
  		'style'					=> $forum_config['o_default_style'],
  		'registered'		=> time(),
  		'registration_ip'		=> get_remote_address(),
  		'activate_key'			=> ($forum_config['o_regs_verify'] == '1') ? '\''.random_key(8, true).'\'' : 'NULL',
  		'require_verification'	=> ($forum_config['o_regs_verify'] == '1'),
  		'notify_admins'	=> ($forum_config['o_regs_report'] == '1')
  	);

  	add_user($user_info, $new_uid);
  	
  }
  
}

/* End fliphack */

?>