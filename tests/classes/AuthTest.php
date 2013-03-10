<?php
/**
 * Tests authentication process
 *
 * @author Yuriy Akopov
 * @date   2013-03-10
 */
class AuthTest extends GoogleAuthenticatorClientTest {
    const
        PRESET_KEY          = 'ABCDEFGHIJKLMNOP',
        PRESET_TIMESTAMP    = 1362947590,
        PRESET_COUNTER      = 4
    ;

    /**
     * Attempts to authenticate by time with an incorrect code
     *
     * @expectedException \GoogleAuthenticator\AuthException
     */
    public function testTotpAuthFail() {
        $client = $this->getClient(self::PRESET_KEY, \GoogleAuthenticator\Client::MODE_TOTP);
        $result = $client->verifyCode('123456', self::PRESET_TIMESTAMP, 2);
    }

    /**
     * Attempts to authenticate by time with a correct code
     */
    public function testTotpAuthSuccess() {
        $client = $this->getClient(self::PRESET_KEY, \GoogleAuthenticator\Client::MODE_TOTP);
        $result = $client->verifyCode('066050', self::PRESET_TIMESTAMP, 2);

        $this->assertInternalType('integer', $result);
    }

    /**
     * Attempts to authenticate by counter with an incorrect code
     *
     * @expectedException \GoogleAuthenticator\AuthException
     */
    public function testHotpAuthFail() {
        $client = $this->getClient(self::PRESET_KEY, \GoogleAuthenticator\Client::MODE_HOTP);
        $result = $client->verifyCode('123456', self::PRESET_COUNTER, 2);
    }

    /**
     * Attempts to authenticate by counter with a correct code
     */
    public function testHotpAuthSuccess() {
        $client = $this->getClient(self::PRESET_KEY, \GoogleAuthenticator\Client::MODE_HOTP);
        $result = $client->verifyCode('709708', self::PRESET_COUNTER, 0);
        $this->assertInternalType('integer', $result);
    }
}
