<?php
/* oauth.php Azure AD oAuth class
 *
 * Katy Nicholson, last updated 17/11/2021
 *
 * https://github.com/CoasterKaty
 * https://katytech.blog/
 * https://twitter.com/coaster_katy
 *
 */

class modOAuth {

	function errorMessage($message) {
		return	'<!DOCTYPE html>
                        <html lang="en">
                        <head>
                                <meta name="viewport" content="width=device-width, initial-scale=1">
                                <title>Error</title>
                                <link rel="stylesheet" type="text/css" href="style.css" />
                        </head>
                        <body>
                        <div id="fatalError"><div id="fatalErrorInner"><span>Something\'s gone wrong!</span>' . $message . '</div></div>
                        </body>
                        </html>';
	}

	function generateRequest($data) {
	        if (_OAUTH_METHOD == 'certificate') {
                        // Use the certificate specified
                        //https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
                        $cert = file_get_contents(_OAUTH_AUTH_CERTFILE);
                        $certKey = openssl_pkey_get_private(file_get_contents(_OAUTH_AUTH_KEYFILE));
                        $certHash = openssl_x509_fingerprint($cert);
                        $certHash = base64_encode(hex2bin($certHash));
                        $caHeader = json_encode(array('alg' => 'RS256', 'typ' => 'JWT', 'x5t' => $certHash));
                        $caPayload = json_encode(array('aud' => 'https://login.microsoftonline.com/' . _OAUTH_TENANTID . '/v2.0',
                                                'exp' => date('U', strtotime('+10 minute')),
                                                'iss' => _OAUTH_CLIENTID,
                                                'jti' => $this->uuid(),
                                                'nbf' => date('U'),
                                                'sub' => _OAUTH_CLIENTID));
                        $caSignature = '';

                        $caData = $this->base64UrlEncode($caHeader) . '.' . $this->base64UrlEncode($caPayload);
                        openssl_sign($caData, $caSignature, $certKey, OPENSSL_ALGO_SHA256);
                        $caSignature = $this->base64UrlEncode($caSignature);
                        $clientAssertion = $caData . '.' . $caSignature;
                        return $data . '&client_assertion=' . $clientAssertion . '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
                } else {
			// Use the client secret instead
                        return $data . '&client_secret=' . urlencode(_OAUTH_SECRET);
                }

	}

	function postRequest($endpoint, $data) {
		$ch = curl_init('https://login.microsoftonline.com/' . _OAUTH_TENANTID . '/oauth2/v2.0/' . $endpoint);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$response = curl_exec($ch);
		if ($cError = curl_error($ch)) {
			echo $this->errorMessage($cError);
			exit;
		}
		curl_close($ch);
		return $response;

	}

	function base64UrlEncode($toEncode) {
                return str_replace('=', '', strtr(base64_encode($toEncode), '+/', '-_'));
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

}
?>
