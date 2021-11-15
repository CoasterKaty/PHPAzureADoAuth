<?php
/* index.php Sample homepage for oAuth Demo project
 *
 * Katy Nicholson, last updated 15/11/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */


// Load the auth module, this will redirect us to login if we aren't already logged in.
include '../inc/auth.php';
try {
	$Auth = new modAuth();
} catch (authException $e) {
	echo '<h1>Error Ocurred</h1>';
	echo $e->getMessage();
	exit;
}
include '../inc/graph.php';
$Graph = new modGraph();
//Display the username, logout link and a list of attributes returned by Azure AD.
$photo = $Graph->getPhoto();
$profile = $Graph->getProfile();

echo '<h1>Hello there, ' . $profile->displayName . ' (' . $Auth->userName . ')</h1>';
echo '<h2><a href="/?action=logout">Log out</a></h2>';
echo 'Your roles in this app are:<ul>';
foreach ($Auth->userRoles as $role) {
    echo '<li>' . $role . '</li>';
}
echo '</ul>';
echo $photo;
echo '<br><br>';
echo 'Profile Graph API output:<pre>';
print_r($profile);
echo '</pre>';
?>


