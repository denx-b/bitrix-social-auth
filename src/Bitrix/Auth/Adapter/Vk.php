<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

/**
 * Class Vk
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Vk extends Adapter
{
    const VERSION = '5.73';
    const NAME = 'Вконтакте';
    const ID = "VKontakte";
    const LOGIN_PREFIX = "VKuser";

    /**
     * @param array $state
     * @return string
     */
    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'client_id' => $this->client_id,
            'redirect_uri' => $this->getServerName(),
            'display' => 'page',
            'response_type' => 'code',
            'scope' => $this->getScope(),
            'state' => urlencode($this->getState($state)),
            'v' => self::VERSION,
        ]);

        return 'https://oauth.vk.com/authorize/?' . $params;
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'email';

        $scope = implode(',', array_unique($this->params['scope']));
        return (string)preg_replace('/\s+/', '', $scope);
    }

    /**
     * @return array
     * @throws \Exception
     */
    protected function getToken(): array
    {
        $json = $this->curl('https://oauth.vk.com/access_token', [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code']
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error_description']);
        }

        if (array_key_exists('expires_in', $array)) {
            $this->token_expires = $array['expires_in'];
        }

        return $array ?: [];
    }

    /**
     * @return int
     */
    protected function getTokenExpires(): int
    {
        if ($this->token_expires == 0) {
            return time() + 3600 * 24 * 365 * 2;
        }

        return intval(time() + $this->token_expires);
    }

    /**
     * @param $tokenResponse
     * @return array
     * @throws \Exception
     */
    protected function getUserInfo($tokenResponse): array
    {
        $json = $this->curl('https://api.vk.com/method/users.get', [
            'access_token' => $tokenResponse['access_token'],
            'user_id' => $tokenResponse['user_id'],
            'fields' => 'bdate,sex,photo_200',
            'v' => self::VERSION
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['error_msg']);
        }

        return $array['response'][0];
    }

    /**
     * @param array $userInfo
     * @return array
     */
    public function getUserFields(array $userInfo): array
    {
        return [
            'NAME' => $userInfo['first_name'],
            'LAST_NAME' => $userInfo['last_name'],
            'PERSONAL_GENDER' => $userInfo['sex'] == 1 ? 'F' : 'M',
            'PERSONAL_BIRTHDAY' => date('d.m.Y', strtotime($userInfo['bdate'])),
            'PERSONAL_PHOTO' => \CFile::MakeFileArray($userInfo['photo_200']),
            'PERSONAL_WWW' => 'https://vk.com/id' . $userInfo['id'],
        ];
    }
}
