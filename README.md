joomla_login
============

A Drupal 6 module that replaces default md5 based password system to a password system that is compatible with Joomla 1.5.

Installation
============

* Issue `git clone https://github.com/m2mdas/joomla_login.git` command in your `sites/all/modules` folder. Alternatively you can download the zip file form github and extract.

* Enable it in admin panel of your site. The module is in `Auth` section.

* After enabling it change the admin password to reflect the new auth system. From now on new users will have salt based password that is compatible with Joomla 1.5 auth system.
