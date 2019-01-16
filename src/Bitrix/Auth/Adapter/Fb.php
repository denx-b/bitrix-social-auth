<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

use Bitrix\Main\Config\Option;

/**
 * Class Fb
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Fb extends Adapter
{
    const NAME = 'Facebook';
    const ID = "Facebook";
    const LOGIN_PREFIX = "FB_";

    public function getAuthUrl(array $state = []): string
    {
        $params = http_build_query([
            'client_id' => $this->client_id,
            'scope' => $this->getScope(),
            'state' => $this->getState($state)
        ]);

        return 'https://www.facebook.com/v2.8/dialog/oauth?' . $params . '&redirect_uri=' . $this->getServerName();
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
        $json = $this->curl('https://graph.facebook.com/v2.8/oauth/access_token', [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->getServerName(),
            'code' => $this->request['code']
        ]);

        $array = json_decode($json, true);

        if (array_key_exists('error', $array)) {
            throw new \Exception($array['error']['message']);
        }

        return $array;
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

        return $array;
    }

    /**
     * @param array $userInfo
     * @return array
     * @throws \Bitrix\Main\ArgumentNullException
     * @throws \Bitrix\Main\ArgumentOutOfRangeException
     */
    public function getUserFields(array $userInfo): array
    {
        $picture = $this->getUserBigPicture($userInfo);
        return [
            'NAME' => $userInfo['first_name'],
            'LAST_NAME' => $userInfo['last_name'],
            'EMAIL' => $userInfo['email'],
            'PERSONAL_GENDER' => $userInfo['sex'] == 'female' ? 'F' : 'M',
            'PERSONAL_PHOTO' => \CFile::MakeFileArray($picture),
            'PERSONAL_WWW' => 'https://www.facebook.com/profile.php?id=' . $userInfo['id'],
        ];
    }

    /**
     * Для facebook'а требуется дополнительное телодвижение для получение картинки большего размера
     *
     * @param $userInfo
     * @return string
     * @throws \Bitrix\Main\ArgumentNullException
     * @throws \Bitrix\Main\ArgumentOutOfRangeException
     */
    protected function getUserBigPicture($userInfo): string
    {
        $picture = 'https://graph.facebook.com/' . $userInfo['id'] . '/picture?type=large';
        $doc_root = $this->context->getServer()->getDocumentRoot();
        $upload_dir = Option::get('main', 'upload_dir', 'upload');
        \CheckDirPath($doc_root . '/' . $upload_dir . '/tmp/');
        $upload = $doc_root . '/' . $upload_dir . '/tmp/' . $userInfo['id'] . '.jpg';

        $file_headers = @get_headers($picture);
        if ($file_headers[0] == 'HTTP/1.1 404 Not Found') {
            $picture = $userInfo['picture']['data']['url'];
        } else {
            if (file_put_contents($upload, file_get_contents($picture))) {
                $picture = $upload;
            } else {
                $picture = $userInfo['picture']['data']['url'];
            }
        }

        return $picture;
    }
}
