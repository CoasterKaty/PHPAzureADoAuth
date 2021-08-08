<?php
/* index.php Sample homepage for oAuth Demo project
 *
 * Katy Nicholson, last updated 08/08/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */


// Load the auth module, this will redirect us to login if we aren't already logged in.
include '../inc/auth.php';
$Auth = new modAuth();

//Display the username, logout link and a list of attributes returned by Azure AD.
echo '<h1>Hello there, ' . $Auth->userName . '</h1>';
echo '<h2><a href="/?action=logout">Log out</a></h2>';
echo '<pre>';
print_r($Auth->userData);
echo '</pre>';
?>

