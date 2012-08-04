<?php
//method names says it all :)

function genRandomPassword($length = 8) {
  $salt = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  $len = strlen($salt);
  $makepass = '';
  mt_srand(10000000 * (double) microtime());

  for ($i = 0; $i < $length; $i++) {
    $makepass .= $salt[mt_rand(0, $len - 1)];
  }

  return $makepass;
}


function getCryptedPassword($plaintext, $salt = '', $encryption = 'md5-hex', $show_encrypt = false) {
  // Get the salt to use.
  $salt = getSalt($encryption, $salt, $plaintext);

  // Encrypt the password.
  switch ($encryption) {
  case 'plain' :
    return $plaintext;

  case 'sha' :
    $encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext));
    return ($show_encrypt) ? '{SHA}' . $encrypted : $encrypted;

  case 'crypt' :
  case 'crypt-des' :
  case 'crypt-md5' :
  case 'crypt-blowfish' :
    return ($show_encrypt ? '{crypt}' : '') . crypt($plaintext, $salt);

  case 'md5-base64' :
    $encrypted = base64_encode(mhash(MHASH_MD5, $plaintext));
    return ($show_encrypt) ? '{MD5}' . $encrypted : $encrypted;

  case 'ssha' :
    $encrypted = base64_encode(mhash(MHASH_SHA1, $plaintext . $salt) . $salt);
    return ($show_encrypt) ? '{SSHA}' . $encrypted : $encrypted;

  case 'smd5' :
    $encrypted = base64_encode(mhash(MHASH_MD5, $plaintext . $salt) . $salt);
    return ($show_encrypt) ? '{SMD5}' . $encrypted : $encrypted;

  case 'aprmd5' :
    $length = strlen($plaintext);
    $context = $plaintext . '$apr1$' . $salt;
    $binary = JUserHelper::_bin(md5($plaintext . $salt . $plaintext));

    for ($i = $length; $i > 0; $i -= 16) {
      $context .= substr($binary, 0, ($i > 16 ? 16 : $i));
    }
    for ($i = $length; $i > 0; $i >>= 1) {
      $context .= ( $i & 1) ? chr(0) : $plaintext[0];
    }

    $binary = JUserHelper::_bin(md5($context));

    for ($i = 0; $i < 1000; $i++) {
      $new = ($i & 1) ? $plaintext : substr($binary, 0, 16);
      if ($i % 3) {
        $new .= $salt;
      }
      if ($i % 7) {
        $new .= $plaintext;
      }
      $new .= ( $i & 1) ? substr($binary, 0, 16) : $plaintext;
      $binary = JUserHelper::_bin(md5($new));
    }

    $p = array();
    for ($i = 0; $i < 5; $i++) {
      $k = $i + 6;
      $j = $i + 12;
      if ($j == 16) {
        $j = 5;
      }
      $p[] = JUserHelper::_toAPRMD5((ord($binary[$i]) << 16) | (ord($binary[$k]) << 8) | (ord($binary[$j])), 5);
    }

    return '$apr1$' . $salt . '$' . implode('', $p) . JUserHelper::_toAPRMD5(ord($binary[11]), 3);

  case 'md5-hex' :
  default :
    $encrypted = ($salt) ? md5($plaintext . $salt) : md5($plaintext);
    return ($show_encrypt) ? '{MD5}' . $encrypted : $encrypted;
  }
}


function getSalt($encryption = 'md5-hex', $seed = '', $plaintext = '') {
  // Encrypt the password.
  switch ($encryption) {
  case 'crypt' :
  case 'crypt-des' :
    if ($seed) {
      return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 2);
    } else {
      return substr(md5(mt_rand()), 0, 2);
    }
    break;
  case 'crypt-md5' :
    if ($seed) {
      return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 12);
    } else {
      return '$1$' . substr(md5(mt_rand()), 0, 8) . '$';
    }
    break;

  case 'crypt-blowfish' :
    if ($seed) {
      return substr(preg_replace('|^{crypt}|i', '', $seed), 0, 16);
    } else {
      return '$2$' . substr(md5(mt_rand()), 0, 12) . '$';
    }
    break;

  case 'ssha' :
    if ($seed) {
      return substr(preg_replace('|^{SSHA}|', '', $seed), -20);
    } else {
      return mhash_keygen_s2k(MHASH_SHA1, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
    }
    break;

  case 'smd5' :
    if ($seed) {
      return substr(preg_replace('|^{SMD5}|', '', $seed), -16);
    } else {
      return mhash_keygen_s2k(MHASH_MD5, $plaintext, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
    }
    break;

  case 'aprmd5' :
    /* 64 characters that are valid for APRMD5 passwords. */
    $APRMD5 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    if ($seed) {
      return substr(preg_replace('/^\$apr1\$(.{8}).*/', '\\1', $seed), 0, 8);
    } else {
      $salt = '';
      for ($i = 0; $i < 8; $i++) {
        $salt .= $APRMD5 {
          rand(0, 63)
        };
      }
      return $salt;
    }
    break;

  default :
    $salt = '';
    if ($seed) {
      $salt = $seed;
    }
    return $salt;
    break;
  }
}


function create_password($pass, $uid){
  $salt = genRandomPassword(32);
  $crypt = getCryptedPassword($pass, $salt);
  $password = $crypt . ':' . $salt;
  db_query("UPDATE {users}  set pass = '%s' where uid = %d", $password, $uid);
}


function check_password($salted_pass, $form_pass){
  $passpart = explode(":", $salted_pass);
  $crypt = $passpart[0];
  $salt = @$passpart[1];
  $gen_crypt = getCryptedPassword(trim($form_pass), $salt);
  return $crypt == $gen_crypt;
}
