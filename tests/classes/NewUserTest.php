<?php
/**
 * Tests functionality related to new user registration / enrollment into 2-factor authentication
 *
 * @author Yuriy Akopov
 * @date   2013-03-10
 */
class NewUserTest extends GoogleAuthenticatorClientTest {
    /*
     * Checks if the keys generated for new user pass their own assertion function
     */
    public function testNewKey() {
        // testing invalid key
        $key = '123457890ABCDEI';
        $this->assertEquals(false, \GoogleAuthenticator\Client::validateKey($key));

        // testing valid key
        $key = 'U23457623ABCDEI5';
        $this->assertEquals(true, \GoogleAuthenticator\Client::validateKey($key));

        // testing random key
        // @todo: this is a flimsy test as it may in theory fail in some cases and not fail in others
        $key = \GoogleAuthenticator\Client::getNewKey();
        $this->assertEquals(true, \GoogleAuthenticator\Client::validateKey($key));
    }

    /**
     * Checks if the URL generations fails on invalid parameters supplied
     *
     * @expectedException \GoogleAuthenticator\Exception
     */
    public function testQrCodeInvaidSize() {
        $client = $this->getClient($this->getKey());

        $client->getQrCodeUrl('GoogleAuthenticatorTest', false, -1);
    }

    /**
     * Checks if the URL returned has valid syntax
     */
    public function testQrCodeValidUrl() {
        $client = $this->getClient($this->getKey());
        $url = $client->getQrCodeUrl('GoogleAuthenticatorTest', 150);

        $this->assertNotEquals(false, filter_var($url, FILTER_VALIDATE_URL));
    }

    /**
     * Checks if the URL returned is answered by Google
     */
    public function testQrCodeUrlExists() {
        $client = $this->getClient($this->getKey());
        $url = $client->getQrCodeUrl('GoogleAuthenticatorTest', 150);

        $httpCode = $this->touchUrl($url);

        $this->assertEquals(200, $httpCode);
    }
}