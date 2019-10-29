<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

/**
 * Class Fb
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Fb extends Adapter
{
    const VERSION = 'v3.0';
    const NAME = 'Facebook';
    const ID = "Facebook";
    const LOGIN_PREFIX = "FB_";

    /**
     * @param array $state
     * @return string
     */
    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'client_id' => $this->client_id,
            'scope' => $this->getScope(),
            'state' => $this->getState($state)
        ]);

        return 'https://www.facebook.com/' . self::VERSION . '/dialog/oauth?' . $params . '&redirect_uri=' .
            $this->getServerName();
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'public_profile';
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
        $json = $this->curl('https://graph.facebook.com/' . self::VERSION . '/oauth/access_token', [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code']
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['message']);
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
        $json = $this->curl('https://graph.facebook.com/me', [
            'access_token' => $tokenResponse['access_token'],
            'fields' => 'id,first_name,last_name,age_range,gender,picture,email'
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['error_msg']);
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
            'NAME' => $userInfo['first_name'],
            'LAST_NAME' => $userInfo['last_name'],
            'EMAIL' => $userInfo['email'],
            'PERSONAL_GENDER' => $userInfo['sex'] == 'female' ? 'F' : 'M',
            'PERSONAL_PHOTO' => \CFile::MakeFileArray($userInfo['picture']['data']['url'])
        ];
    }
}
