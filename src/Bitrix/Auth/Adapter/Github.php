<?php

namespace Dbogdanoff\Bitrix\Auth\Adapter;

use Exception;

/**
 * Class Github
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Github extends Adapter
{
    const NAME = 'GitHub';
    const ID = 'GitHub'; // EXTERNAL_AUTH_ID
    const LOGIN_PREFIX = 'GH_';

    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'client_id' => $this->client_id,
            'redirect_uri' => $this->getServerName(),
            'scope' => $this->getScope(),
            'state' => $this->getState($state)
        ]);

        return 'https://github.com/login/oauth/authorize?' . $params;
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'read:user';
        $this->params['scope'][] = 'user:email';

        return implode(' ', array_unique($this->params['scope']));
    }

    /**
     * @return array
     * @throws Exception
     */
    protected function getToken(): array
    {
        $uri = $this->curl('https://github.com/login/oauth/access_token', [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code']
        ], true);

        parse_str($uri, $array);

        if (array_key_exists('error', $array)) {
            throw new Exception($array['error_description'] . ' (' . $array['error'] . ')');
        }

        if (array_key_exists('access_token', $array)) {
            $this->token = $array['access_token'];
        }

        return $array ?: [];
    }

    /**
     * @return int
     */
    protected function getTokenExpires(): int
    {
        return intval(time() + $this->token_expires);
    }

    /**
     * @param $tokenResponse
     * @return array
     * @throws Exception
     */
    protected function getUserInfo($tokenResponse): array
    {
        $url = 'https://api.github.com/user';
        $data = ['access_token' => $tokenResponse['access_token']];
        $bearer = ['Authorization: token ' . $this->token];
        $json = $this->curl($url, $data, false, $bearer);
        $array = json_decode($json, true);
        return $array ?: [];
    }

    /**
     * @param array $userInfo
     * @return array
     */
    public function getUserFields(array $userInfo): array
    {
        $arFields = [
            'EMAIL' => $userInfo['email'],
            'PERSONAL_PHOTO' => $this->downloadPictureToTemp($userInfo['avatar_url'])
        ];

        $expName = explode(' ', $userInfo['name']);
        $arFields['NAME'] = $expName[0];
        if ($expName[1]) {
            $arFields['LAST_NAME'] = $expName[1];
        }

        return $arFields;
    }
}
