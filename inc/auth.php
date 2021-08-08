<?php
/* auth.php Azure AD oAuth Class
 *
 * Katy Nicholson, last updated 08/08/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */

require_once dirname(__FILE__) . '/mysql.php';

class modAuth {
    var $modDB;
    var $userData;
    var $userName;
    var $oAuthVerifier;
    var $oAuthChallenge;
    var $oAuthChallengeMethod;

    function __construct() {
        $this->modDB = new modDB();

        session_start();
        // check session key against database. If it's expired or doesnt exist then forward to Azure AD
        $url = _URL . $_SERVER['REQUEST_URI'];

        if (isset($_SESSION['sessionkey'])) {
            // see if it's still valid
            $res = $this->modDB->QuerySingle('SELECT * FROM tblAuthSessions WHERE txtSessionKey = \'' . $this->modDB->Escape($_SESSION['sessionkey']) . '\' AND dtExpires > NOW()');
            $this->oAuthVerifier = $res['txtCodeVerifier'];
            $this->oAuthChallenge();
            if (!$res || !$res['txtJWT']) {
                //not in DB or empty JWT field
                unset($_SESSION['sessionkey']);
                session_destroy();
                header('Location: ' . $_SERVER['REQUEST_URI']);
                exit;
            }
            if ($_GET['action'] == 'logout') {
                $this->modDB->Delete('tblAuthSessions', array('intAuthID' => $res['intAuthID']));
                unset($_SESSION['sessionkey']);
                session_destroy();
                header('Location: ' . _OAUTH_LOGOUT);
                exit;
            }
            if (strtotime($res['dtExpires']) < strtotime('+10 minutes')) {
                //attempt token refresh
                if ($res['txtRefreshToken']) {
                    $oauthRequest = 'grant_type=refresh_token&refresh_token=' . $res['txtRefreshToken'] . '&client_id=' . _OAUTH_CLIENTID . '&client_secret=' . urlencode(_OAUTH_SECRET) . '&scope=openid%20offline_access';
                    $ch = curl_init(_OAUTH_SERVER . 'token');
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $oauthRequest);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    $response = curl_exec($ch);
                    curl_close($ch);
                    $reply = json_decode($response);
                    if ($reply->error) {
                        if(substr($reply->error_description, 0, 9) == 'MSIS9615:') {
                            //refresh token expired
                            $this->modDB->Update('tblAuthSessions', array('txtRedir' => $url, 'txtRefreshToken' => ''),  array('intAuthID' => $res['intAuthID']));
                            $oAuthURL = _OAUTH_SERVER . 'authorize?response_type=code&client_id=' . _OAUTH_CLIENTID . '&redirect_uri=' . urlencode(_URL . '/oauth.php') . '&scope=openid%20offline_access';
                            header('Location: ' . $oAuthURL);
                            exit;
                        }
                    die($reply->error_description);
                    }
                    $jwt = explode('.', $reply->access_token);
                    $info = json_decode(base64_decode($jwt[1]), true);
                    $this->modDB->Update('tblAuthSessions', array('txtRefreshToken' => $reply->refresh_token, 'txtJWT' => base64_decode($jwt[1]), 'txtRedir' => '', 'dtExpires' => date('Y-m-d H:i:s', strtotime('+' . $reply->expires_in . ' seconds'))), array('intAuthID' => $res['intAuthID']));
                }
            }
            $this->userData = json_decode($res['txtJWT']);
            $this->userName = $this->userData->unique_name;
        } else {
            $this->oAuthChallenge();
            $sessionKey = $this->uuid();
            $_SESSION['sessionkey'] = $sessionKey;
            $this->modDB->Insert('tblAuthSessions', array('txtSessionKey' => $sessionKey, 'txtRedir' => $url, 'txtCodeVerifier' => $this->oAuthVerifier, 'dtExpires' => date('Y-m-d H:i:s', strtotime('+5 minutes'))));
            $oAuthURL = _OAUTH_SERVER . 'authorize?response_type=code&client_id=' . _OAUTH_CLIENTID . '&redirect_uri=' . urlencode(_URL . '/oauth.php') . '&scope=openid%20offline_access&code_challenge=' . $this->oAuthChallenge . '&code_challenge_method=' . $this->oAuthChallengeMethod;
            header('Location: ' . $oAuthURL);
            exit;
        }
        //Clean up old entries
        $this->modDB->Query('DELETE FROM tblAuthSessions WHERE dtExpires < NOW()');
    }

    function uuid() {
        //uuid function is not my code, but unsure who the original author is. KN
        //uuid version 4
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
            // 16 bits for "time_mid"
            mt_rand( 0, 0xffff ),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand( 0, 0x0fff ) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand( 0, 0x3fff ) | 0x8000,
            // 48 bits for "node"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }

    function oAuthChallenge() {
        $verifier = $this->oAuthVerifier;
        if (!$this->oAuthVerifier) {
            $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~';
            $charLen = strlen($chars);
            $verifier = '';
            for ($i = 0; $i < 128; $i++) {
                $verifier .= $chars[mt_rand(0, $charLen)];
            }
            $this->oAuthVerifier = $verifier;
        }
        // Challenge = Base64 Url Encode ( SHA256 ( Verifier ) )
        // Pack (H) to convert 64 char hash into 32 byte hex
        // As there is no B64UrlEncode we use strtr to swap +/ for -_ and then strip off the =
        $this->oAuthChallenge = str_replace('=', '', strtr(base64_encode(pack('H*', hash('sha256', $verifier))), '+/', '-_'));
        $this->oAuthChallengeMethod = 'S256'; //change to S256
    }
}
?>

