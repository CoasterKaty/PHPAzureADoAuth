<?php
/* config.inc Configuration for oAuth Demo project
 *
 * Katy Nicholson, last updated 15/11/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */

// MySQL connection details
define('_MYSQL_HOST', 'localhost');
define('_MYSQL_USER', 'oauthdemo');
define('_MYSQL_DB', 'oauthdemo');
define('_MYSQL_PASS', 'DATABASE_PASSWORD');


// oAuth details

// tenant ID = only users in your tenant and guests can log in (unless you also select MS personal accounts), other tenants get "This user is not a guest in the target tenant" error
// common = any tenant can log in, doesn't have to be a guest
//Scope needs to include the services you wish to access - at a minimum you'll need openid and offline_access for logging on to work. Add in user.read if you want to query user profile via Graph. Separate with %20.

//define('_OAUTH_SERVER', 'https://login.microsoftonline.com/common/oauth2/v2.0/');
define('_OAUTH_SERVER', 'https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/');
define('_OAUTH_CLIENTID', 'CLIENT_ID');
define('_OAUTH_TENANTID', 'TENANT_ID');
define('_OAUTH_LOGOUT', 'https://login.microsoftonline.com/common/wsfederation?wa=wsignout1.0');
define('_OAUTH_SECRET', 'CLIENT_SECRET');
define('_OAUTH_SCOPE', 'openid%20offline_access%20profile%20user.read');



define('_URL', 'https://oauthdemo.k80.cat');
?>

