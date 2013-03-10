<?php
/**
 * Base class for all the GoogleAuthenticatorClient test
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */
abstract class GoogleAuthenticatorClientTest extends PHPUnit_Framework_TestCase
{
    /**
     * Generates a new user key
     *
     * @return string
     */
    public function getKey() {
        return \GoogleAuthenticator\Client::getNewKey();
    }

    /**
     * Initialised and returns new client instance
     *
     * @param   string  $key
     *
     * @return GoogleAuthenticator\Client
     */
    public function getClient($key, $mode = \GoogleAuthenticator\Client::MODE_TOTP) {
        $client = new \GoogleAuthenticator\Client($key, $mode);

        return $client;
    }

    /**
     * Tries to open the URL given and returns resulting HTTP code
     *
     * @param   string  $url
     *
     * @return  int
     */
    public function touchUrl($url) {
        $ch = curl_init();

        $options = array(
            CURLOPT_URL             => $url,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_HEADER          => true,
            CURLOPT_FOLLOWLOCATION  => true,
            CURLOPT_ENCODING        => '',
            CURLOPT_AUTOREFERER     => true,
            CURLOPT_CONNECTTIMEOUT  => 120,
            CURLOPT_TIMEOUT         => 120,
            CURLOPT_MAXREDIRS       => 10,
            CURLOPT_SSL_VERIFYPEER  => false
        );
        curl_setopt_array( $ch, $options );
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        print curl_error($ch);
        curl_close($ch);

        return $httpCode;
    }
}
