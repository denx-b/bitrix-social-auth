<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

class Inst extends Adapter
{
    const NAME = 'Instagram';
    const ID = "Instagram"; // EXTERNAL_AUTH_ID
    const LOGIN_PREFIX = "inst_";

    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'app_id' => $this->client_id,
            'redirect_uri' => $this->getServerName(),
            'scope' => $this->getScope(),
            'response_type' => 'code',
            'state' => $this->getState($state)
        ]);

        return 'https://api.instagram.com/oauth/authorize/?' . $params;
    }

    /**
     * Возвращает строку прав доступа
     * @return string
     */
    protected function getScope(): string
    {
        $this->params['scope'] = (array)$this->params['scope'];
        $this->params['scope'][] = 'user_profile';
        $this->params['scope'][] = 'user_media';

        $scope = implode(',', array_unique($this->params['scope']));
        return preg_replace('/\s+/', '', $scope);
    }

    /**
     * @return array
     * @throws \Exception
     */
    protected function getToken(): array
    {
        $json = $this->curl('https://api.instagram.com/oauth/access_token', [
            'app_id' => $this->client_id,
            'app_secret' => $this->client_secret,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code']
        ], true);

        $array = json_decode($json, true);

        if (array_key_exists('error_description', $array)) {
            throw new \Exception($array['error_description']);
        }

        return $array ?: [];
    }

    /**
     * @return int
     */
    protected function getTokenExpires(): int
    {
        return time() + 3600;
    }

    /**
     * @param $tokenResponse
     * @return array
     * @throws \Exception
     */
    protected function getUserInfo($tokenResponse): array
    {
        $json = $this->curl('https://graph.instagram.com/' . $tokenResponse['user_id'], array(
            'access_token' => $tokenResponse['access_token'],
            'fields' => 'id,username'
        ));

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['message']);
        }

        return $array ?: [];
    }

    protected function getUserFields(array $userInfo): array
    {
        return [
            'NAME' => $userInfo['full_name'] ?: $userInfo['username'],
            'PERSONAL_WWW' => 'https://www.instagram.com/' . $userInfo['username'] .'/'
        ];
    }
}
