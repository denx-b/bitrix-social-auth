<?php

namespace Dbogdanoff\Bitrix\Auth\Adapter;

use Exception;

/**
 * Class Telegram
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Telegram extends Adapter
{
    const NAME = 'Telegram';
    const ID = 'Telegram'; // EXTERNAL_AUTH_ID
    const LOGIN_PREFIX = 'TG_';

    public function getAuthUrl(array $state = []): string
    {
        $exp = explode(':', $this->client_secret);
        $params = http_build_query([
            'bot_id' => $exp[0],
            'origin' => $this->getServerName(),
            'embed' => false,
        ]);

        return 'https://oauth.telegram.org/auth?' . $params;
    }

    public function getButton(string $selector, string $size = 'large', string $redirect = '/'): string
    {
        $size = !in_array($size, ['large', 'medium', 'small']) ? 'large' : $size;
        return <<<HTML
        <script>
        let script = document.createElement("script");
        script.type = "text/javascript";
        script.dataset.telegramLogin = "{$this->client_id}";
        script.dataset.size = "{$size}";
        script.dataset.authUrl = "{$redirect}";
        script.onload = function () {
            let el = document.querySelector("{$selector}");
            el.append(document.querySelector('#telegram-login-{$this->client_id}'));
        };
        script.src = "https://telegram.org/js/telegram-widget.js?2";
        document.getElementsByTagName("head")[0].appendChild(script);
        </script>
HTML;
    }

    /**
     * @return array
     * @throws Exception
     */
    protected function getToken(): array
    {
        return ['access_token' => $this->client_secret];
    }

    /**
     * @return int
     */
    protected function getTokenExpires(): int
    {
        return $this->request->get('auth_date');
    }

    /**
     * @param $token
     * @return array
     * @throws Exception
     */
    protected function getUserInfo($token): array
    {
        return $this->request->toArray();
    }

    /**
     * @param array $userInfo
     * @return array
     */
    public function getUserFields(array $userInfo): array
    {
        $arFields = [
            'NAME' => $userInfo['first_name'] ?:
                $userInfo['username'] ?: $userInfo['id']
        ];

        if ($userInfo['last_name']) {
            $arFields['LAST_NAME'] = $userInfo['last_name'];
        }

        if ($userInfo['photo_url']) {
            $arFields['PERSONAL_PHOTO'] = $this->downloadPictureToTemp($userInfo['photo_url']);
        }

        return $arFields;
    }

    protected function specialCheck(): bool
    {
        $auth_data = $this->request->toArray();
        $check_hash = $auth_data['hash'];
        unset($auth_data['hash']);
        $data_check_arr = [];
        foreach ($auth_data as $key => $value) {
            $data_check_arr[] = $key . '=' . $value;
        }
        sort($data_check_arr);
        $data_check_string = implode("\n", $data_check_arr);
        $secret_key = hash('sha256', $this->client_secret, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);
        if (strcmp($hash, $check_hash) !== 0) {
            return false;
        }
        if ((time() - $auth_data['auth_date']) > 86400) {
            return false;
        }
        return true;
    }
}
