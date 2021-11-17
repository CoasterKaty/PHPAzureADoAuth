<?php
/* oauth.php Azure AD oAuth web callback script
 *
 * Katy Nicholson, last updated 17/11/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */
require_once '../inc/mysql.php';
require_once '../inc/oauth.php';


session_start();
$modDB = new modDB();
$oAuth = new modOAuth();
if ($_GET['error']) {
	echo $oAuth->errorMessage($_GET['error_description']);
	exit;
}
//retrieve session data from database
$sessionData = $modDB->QuerySingle('SELECT * FROM tblAuthSessions WHERE txtSessionKey=\'' . $modDB->Escape($_SESSION['sessionkey']) . '\'');

if ($sessionData) {
    // Request token from Azure AD
	$oauthRequest = $oAuth->generateRequest('grant_type=authorization_code&client_id=' . _OAUTH_CLIENTID . '&redirect_uri=' . urlencode(_URL . '/oauth.php') . '&code=' . $_GET['code'] . '&code_verifier=' . $sessionData['txtCodeVerifier']);

	$response = $oAuth->postRequest('token', $oauthRequest);

	// Decode response from Azure AD. Extract JWT data from supplied access_token and id_token and update database.
	if (!$response) { 
		echo $oAuth->errorMessage('Unknown error acquiring token');
		exit;
	}
	$reply = json_decode($response);
	if ($reply->error) {
	        echo $oAuth->errorMessage($reply->error_description);
		exit;
	}

	$idToken = base64_decode(explode('.', $reply->id_token)[1]);
	$modDB->Update('tblAuthSessions', array('txtToken' => $reply->access_token, 'txtRefreshToken' => $reply->refresh_token, 'txtIDToken' => $idToken, 'txtRedir' => '', 'dtExpires' => date('Y-m-d H:i:s', strtotime('+' . $reply->expires_in . ' seconds'))), array('intAuthID' => $sessionData['intAuthID']));
	// Redirect user back to where they came from.
	header('Location: ' . $sessionData['txtRedir']);
} else {
	header('Location: /');
}
?>
