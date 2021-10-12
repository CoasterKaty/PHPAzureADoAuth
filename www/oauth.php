<?php
/* oauth.php Azure AD oAuth web callback script
 *
 * Katy Nicholson, last updated 01/09/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */
require_once '../inc/mysql.php';

session_start();
$modDB = new modDB();
if ($_GET['error']) {
    die($_GET['error_description']);
    exit;
}
//retrieve session data from database
$sessionData = $modDB->QuerySingle('SELECT * FROM tblAuthSessions WHERE txtSessionKey=\'' . $modDB->Escape($_SESSION['sessionkey']) . '\'');


if ($sessionData) {
    // Request token from Azure AD
    $oauthRequest = 'grant_type=authorization_code&client_id=' . _OAUTH_CLIENTID . '&redirect_uri=' . urlencode(_URL . '/oauth.php') . '&code=' . $_GET['code'] . '&client_secret=' . urlencode(_OAUTH_SECRET) . '&code_verifier=' . $sessionData['txtCodeVerifier'];
    $ch = curl_init(_OAUTH_SERVER . 'token');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $oauthRequest);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $response = curl_exec($ch);
    if ($cError = curl_error($ch)) {
        die($cError);
    }
    curl_close($ch);
    // Decode response from Azure AD. Extract JWT data from supplied access_token and update database.
    $reply = json_decode($response);
    if ($reply->error) {
        die($reply->error_description);
    }
    $jwt = explode('.', $reply->access_token);
    $info = json_decode(base64_decode($jwt[1]), true);
    $modDB->Update('tblAuthSessions', array('txtToken' => $reply->access_token, 'txtRefreshToken' => $reply->refresh_token, 'txtJWT' => base64_decode($jwt[1]), 'txtRedir' => '', 'dtExpires' => date('Y-m-d H:i:s', strtotime('+' . $reply->expires_in . ' seconds'))), array('intAuthID' => $sessionData['intAuthID']));
    // Redirect user back to where they came from.
    header('Location: ' . $sessionData['txtRedir']);
} else {
    header('Location: /');
}
?>
