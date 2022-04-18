<?php

namespace Dbogdanoff\Bitrix\Auth\Adapter;

use Exception;

/**
 * Class Ok
 * @package Bitrix Social Auth
 */
class Ok extends Adapter
{
    const NAME = 'Одноклассники';
    const ID = "Odnoklassniki";
    const LOGIN_PREFIX = "OKuser";

    /**
     * @param array $state
     * @return string
     */
    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'client_id' => $this->client_id,
            'scope' => $this->getScope(),
            'response_type' => 'code',
            'state' => $this->getState($state),
        ]);

        return 'https://connect.ok.ru/oauth/authorize?' . $params . '&redirect_uri=' .
            $this->getServerName();
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'VALUABLE_ACCESS';
        $this->params['scope'][] = 'LONG_ACCESS_TOKEN';
        $this->params['scope'][] = 'GET_EMAIL';

        $scope = implode(',', array_unique($this->params['scope']));
        return (string)preg_replace('/\s+/', '', $scope);
    }

    /**
     * @return array
     * @throws \Exception
     */
    protected function getToken(): array
    {
        $query = http_build_query([
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code'],
            'grant_type' => 'authorization_code',
        ]);
        $json = $this->curl('https://api.ok.ru/oauth/token.do?' . $query, [], true);

        $array = json_decode($json, true);

        if (array_key_exists('error_msg', $array)) {
            throw new Exception($array['error_msg']);
        }

        if (array_key_exists('access_token', $array)) {
            $this->token = $array['access_token'];
        }

        if (array_key_exists('expires_in', $array)) {
            $this->token_expires = intval($array['expires_in']);
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
     * @param $token
     * @return array
     * @throws \Exception
     */
    protected function getUserInfo($token): array
    {
        $userId = $this->getUserId();

        $fields = ['first_name', 'last_name', 'email', 'gender', 'pic_full'];

        $secret_key = md5($this->token . $this->client_secret);
        $sig = md5(
            'application_key=' . $this->params['client_pub_key'] . 'fields=' . implode(', ', $fields)
            . 'format=jsonmethod=users.getInfouids=' . $userId . $secret_key
        );

        $json = $this->curl('https://api.ok.ru/fb.do', [
            'application_key' => $this->params['client_pub_key'],
            'fields' => implode(', ', $fields),
            'format' => 'json',
            'method' => 'users.getInfo',
            'uids' => $userId,
            'sig' => $sig,
            'access_token' => $token['access_token'],
        ]);

        list($array) = json_decode($json, true);

        if (array_key_exists('error_msg', $array)) {
            throw new Exception($array['error_msg']);
        }
        $array['id'] = $array['uid'];

        return $array ?: [];
    }

    /**
     * @param array $userInfo
     * @return array
     */
    protected function getUserFields(array $userInfo): array
    {
        return [
            'NAME' => $userInfo['first_name'],
            'LAST_NAME' => $userInfo['last_name'],
            'EMAIL' => $userInfo['email'],
            'PERSONAL_GENDER' => $userInfo['gender'] == 'male' ? 'M' : 'F',
            'PERSONAL_PHOTO' => $this->downloadPictureToTemp($userInfo['pic_full']),
        ];
    }

    /**
     * Получение UID пользователя.
     * @throws \Exception
     */
    protected function getUserId()
    {
        $secret_key = md5($this->token . $this->client_secret);
        $sig = md5(
            'application_key=' . $this->params['client_pub_key'] . 'format=jsonmethod=users.getLoggedInUser' . $secret_key
        );

        $json = $this->curl('https://api.ok.ru/fb.do', [
            'application_key' => $this->params['client_pub_key'],
            'format' => 'json',
            'method' => 'users.getLoggedInUser',
            'sig' => $sig,
            'access_token' => $this->token,
        ]);

        $response = json_decode($json, true);

        if (is_array($response) && array_key_exists('error_msg', $response)) {
            throw new Exception($response['error_msg']);
        }

        return $response ?: '';
    }
}
