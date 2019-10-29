<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

/**
 * Class Google
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Google extends Adapter
{
    const VERSION = 'v2';
    const NAME = 'Google';
    const ID = "GoogleOAuth"; // EXTERNAL_AUTH_ID
    const LOGIN_PREFIX = "G_";

    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'scope' => $this->getScope(),
            'state' => $this->getState($state),
            'redirect_uri' => $this->getServerName(),
            'response_type' => 'code',
            'client_id' => $this->client_id
        ]);

        return 'https://accounts.google.com/o/oauth2/' . self::VERSION . '/auth?' . $params;
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'https://www.googleapis.com/auth/userinfo.profile';
        $this->params['scope'][] = 'https://www.googleapis.com/auth/userinfo.email';

        return implode(' ', array_unique($this->params['scope']));
    }

    /**
     * @return array
     * @throws \Exception
     */
    protected function getToken(): array
    {
        $json = $this->curl('https://www.googleapis.com/oauth2/v4/token', [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code'],
            'grant_type' => 'authorization_code'
        ], true);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error_description'] . ' (' . $array['error'] . ')');
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
     * @param $tokenResponse
     * @return array
     * @throws \Exception
     */
    protected function getUserInfo($tokenResponse): array
    {
        $json = $this->curl('https://www.googleapis.com/oauth2/' . self::VERSION . '/userinfo', [
            'access_token' => $tokenResponse['access_token'],
            'fields' => 'id,link,given_name,family_name,gender,picture,email'
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['message']);
        }

        return $array ?: [];
    }

    /**
     * @param array $userInfo
     * @return array
     */
    public function getUserFields(array $userInfo): array
    {
        return [
            'NAME' => $userInfo['given_name'],
            'LAST_NAME' => $userInfo['family_name'],
            'EMAIL' => $userInfo['email'],
            'PERSONAL_GENDER' => $userInfo['sex'] == 'female' ? 'F' : 'M',
            'PERSONAL_PHOTO' => \CFile::MakeFileArray($userInfo['picture']),
            'PERSONAL_WWW' => $userInfo['link'],
        ];
    }
}
