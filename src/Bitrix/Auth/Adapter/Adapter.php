<?

namespace Dbogdanoff\Bitrix\Auth\Adapter;

use Bitrix\Main\Application;
use Bitrix\Main\DB\Result;
use Bitrix\Main\Loader;
use Bitrix\Socialservices\UserTable;

/**
 * Class Adapter
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
abstract class Adapter
{
    /**
     * Идентификатор приложения.
     * Может быть объявлен в адаптере или передан в конструктор, при создании объекта
     *
     * @var string
     */
    protected $client_id;

    /**
     * Защищенный ключ приложения.
     * Может быть объявлен в адаптере или передан в конструктор, при создании объекта
     *
     * @var string
     */
    protected $client_secret;

    /**
     * Название соц. сети.
     * Чаще всего используется для вывода в публичной части
     *
     * @var string
     */
    const NAME = '';

    /**
     * ID соц. сети в системе Bitrix.
     * Используется в поле EXTERNAL_AUTH_ID таблицы b_socialservices_user
     *
     * @var string
     */
    const ID = '';

    /**
     * Префикс для генерации логина.
     *
     * @var string
     */
    const LOGIN_PREFIX = '';

    /** @var array */
    protected $params = [];

    /** @var array */
    protected $baseState = [];

    /** @var \Bitrix\Main\Context */
    protected $context;

    /** @var \Bitrix\Main\HttpRequest */
    protected $request;

    /**
     * На указанную в св-ве стр. пользователь будет отправлен после авторизации.
     * При вызове метода getAuthUrl в первом аргументе в ключе 'page' можно указать адрес редиректа
     * По-умолчанию это адрес с которой пользователь перешёл для разрешения прав в свою соц. сеть
     *
     * @var string
     */
    private static $redirectTo = '/';

    /**
     * Должен содержать как минимум client_id и client_secret
     * И client_id и client_secret также могут быть сразу объявлены в адаптере
     *
     * @param array $params
     * @throws \Exception
     */
    public function __construct(array $params = [])
    {
        $this->context = Application::getInstance()->getContext();
        $this->request = $this->context->getRequest();

        $this->params = $params;

        if ($this->params['client_id']) {
            $this->client_id = $this->params['client_id'];
        } else {
            if (!$this->client_id) {
                throw new \Exception('client_id params can\'t be empty');
            }
        }

        if ($this->params['client_secret']) {
            $this->client_secret = $this->params['client_secret'];
        } else {
            if (!$this->client_secret) {
                throw new \Exception('client_secret params can\'t be empty');
            }
        }
    }

    /**
     * Возвращает адрес куда надо отправить пользователя для разрешения запрошенных прав.
     *
     * @param array $state
     * @return mixed
     */
    abstract public function getAuthUrl(array $state = []): string;

    /**
     * Получение токена.
     *
     * @return array
     * @throws \Exception
     */
    abstract protected function getToken(): array;

    /**
     * Запрос на получение информации о пользователе.
     *
     * @param $token
     * @return array
     */
    abstract protected function getUserInfo($token): array;

    /**
     * Принимает массив с метода getUserInfo
     * Должен вернуть массив с ключами для таблицы b_user
     *
     * @param array $userInfo
     * @return array
     */
    abstract protected function getUserFields(array $userInfo): array;

    /**
     * Данный метод вызывается автоматически.
     * Метод регистрирует или авториз. пользователя
     * Если в текущий момент пользователь уже авторизован, привязывает соц. сеть как дополнительную
     * что пользоляет пользователю использовать несколько соц. сетей для авторизации
     *
     * @throws \Bitrix\Main\ArgumentException
     * @throws \Bitrix\Main\LoaderException
     * @throws \Bitrix\Main\ObjectPropertyException
     * @throws \Exception
     */
    public function oauth()
    {
        $tokenResponse = $this->getToken();

        if ($tokenResponse['access_token']) {
            $userInfo = $this->getUserInfo($tokenResponse);
            array_walk_recursive($userInfo, function (&$item) {
                $item = strip_tags($item);
            });

            $email = $tokenResponse['email'] ?: $userInfo['email'];

            if ($uid = $userInfo['id']) {
                $login = static::LOGIN_PREFIX . $uid;

                $dbResUser = $this->userFind(static::ID, $uid);

                $userFields = $this->getUserFields($userInfo);
                $userFields['EMAIL'] = check_email($email) ? $email : $login . '@' . $this->context->getServer()->getServerName();
                $userFields['LOGIN'] = $login;
                $userFields['XML_ID'] = $uid;

                $user = new \CUser;
                if ($user->IsAuthorized()) {
                    if ($dbResUser->fetch()) {
                        throw new \Exception('Авторизация данным аккаунтом "' . static::NAME . '"" уже существует.');
                    } else {
                        $arFile = \CFile::MakeFileArray($userFields['PERSONAL_PHOTO']);
                        $arFile['MODULE_ID'] = 'socialservices';
                        $file_id = \CFile::SaveFile($arFile, $arFile['MODULE_ID']);

                        $this->userAddLink([
                            'NAME' => $userFields['NAME'],
                            'LAST_NAME' => $userFields['LAST_NAME'],
                            'PERSONAL_PHOTO' => $file_id,
                            'EXTERNAL_AUTH_ID' => static::ID,
                            'USER_ID' => $user->GetID(),
                            'CAN_DELETE' => 'Y',
                            'PERSONAL_WWW' => $userFields['PERSONAL_WWW'],
                            'SEND_ACTIVITY' => 'Y',
                            'SITE_ID' => SITE_ID,
                        ]);
                    }

                    $state = $this->parseState();
                    if (strlen($state['page']) > 1) {
                        static::$redirectTo = $state['page'];
                    }
                    \AddEventHandler('main', 'OnEpilog', ['\Dbogdanoff\Bitrix\Auth\Adapter\Adapter', 'redirectToStartPage']);
                } else {
                    if ($arUser = $dbResUser->fetch()) {
                        $this->authorize($arUser['USER_ID']);
                    } else {
                        $this->register($userFields);
                    }
                }
            }
        } else {
            throw new \Exception('Не удалось авторизоваться. Повторите попытку позже.');
        }
    }

    /**
     * Регистрация.
     * Регистрирует пользователя и добавляет запись в табилцу b_socialservices_user
     *
     * @param $fields
     * @throws \Bitrix\Main\ArgumentException
     * @throws \Bitrix\Main\ObjectPropertyException
     * @throws \Exception
     */
    private function register($fields)
    {
        $user = new \CUser;
        $password = $this->randomPassword();

        $result = $user->Register($fields['LOGIN'], $fields['NAME'], $fields['LAST_NAME'], $password, $password,
            $fields['EMAIL']);

        if ($result['TYPE'] == 'ERROR') {
            throw new \Exception($result['MESSAGE']);
        }

        $user_id = $user->GetID();

        $user->Update($user_id, [
            'PERSONAL_GENDER' => $fields['PERSONAL_WWW'],
            'PERSONAL_BIRTHDAY' => $fields['PERSONAL_BIRTHDAY'],
            'PERSONAL_PHOTO' => $fields['PERSONAL_PHOTO'],
            'PERSONAL_WWW' => $fields['PERSONAL_WWW']
        ]);

        $arPhoto = UserTable::getList([
            'filter' => ['ID' => $user_id],
            'select' => ['PERSONAL_PHOTO']
        ])->fetch();

        $this->userAddLink([
            'LOGIN' => $fields['LOGIN'],
            'NAME' => $fields['NAME'],
            'LAST_NAME' => $fields['LAST_NAME'],
            'EMAIL' => $fields['EMAIL'],
            'PERSONAL_PHOTO' => $arPhoto['PERSONAL_PHOTO'],
            'EXTERNAL_AUTH_ID' => static::ID,
            'USER_ID' => $user_id,
            'XML_ID' => $fields['XML_ID'],
            'CAN_DELETE' => 'N',
            'PERSONAL_WWW' => $fields['PERSONAL_WWW'],
            'SEND_ACTIVITY' => 'Y',
            'SITE_ID' => SITE_ID,
        ]);

        $state = $this->parseState();
        if (strlen($state['page']) > 1) {
            static::$redirectTo = $state['page'];
        }
        \AddEventHandler('main', 'OnEpilog', ['\Dbogdanoff\Bitrix\Auth\Adapter\Adapter', 'redirectToStartPage']);
    }

    /**
     * Авторизация.
     *
     * @param $user_id
     * @return bool
     */
    private function authorize($user_id)
    {
        \AddEventHandler('main', 'OnEpilog', ['\Dbogdanoff\Bitrix\Auth\Adapter\Adapter', 'redirectToStartPage']);

        $user = new \CUser;
        return $user->Authorize($user_id, true);
    }

    /**
     * Header Location to static::$redirectTo
     */
    public static function redirectToStartPage()
    {
        \LocalRedirect(static::$redirectTo);
    }

    /**
     * Поиск пользователя по привязке.
     *
     * @param $type
     * @param $xml_id
     * @return Result
     * @throws \Bitrix\Main\ArgumentException
     * @throws \Bitrix\Main\LoaderException
     * @throws \Bitrix\Main\ObjectPropertyException
     * @throws \Bitrix\Main\SystemException
     */
    private function userFind($type, $xml_id): Result
    {
        Loader::includeModule('socialservices');
        return UserTable::getList([
            'filter' => [
                'EXTERNAL_AUTH_ID' => $type,
                'XML_ID' => $xml_id,
                'SITE_ID' => SITE_ID
            ],
            'select' => ['ID', 'USER_ID', 'EMAIL', 'USER_TABLE_EMAIL' => 'USER.EMAIL']
        ]);
    }

    /**
     * Добавление записи в таблицу b_socialservices_user
     *
     * @param $fields
     * @return bool
     * @throws \Exception
     */
    private function userAddLink($fields): bool
    {
        Loader::includeModule('socialservices');
        $result = UserTable::add($fields);
        if (!$result->isSuccess()) {
            throw new \Exception(implode("\n", $result->getErrorMessages()));
        }

        return true;
    }

    /**
     * Дополнительная строка, которая передаётся и возвращается соц. сетью,
     * для повышенной конкретизации адаптера
     *
     * @return mixed
     */
    private function getCheckString(): string
    {
        $adapter = $this->getAdapterBasename();
        return substr(md5($adapter), 0, 6);
    }

    /**
     * @return string
     */
    private function getAdapterBasename(): string
    {
        $className = strtolower(static::class);

        if ($pos = strrpos($className, '\\')) {
            $className = substr($className, $pos + 1);
        }

        return $className;
    }

    /**
     * Возвращает домен с протоколом.
     *
     * @return string
     */
    protected function getServerName(): string
    {
        $url = $this->request->isHttps() ? 'https://' : 'http://';
        $url .= $this->context->getServer()->getServerName() . '/';

        return $url;
    }

    /**
     * @param $state
     * @return string
     */
    protected function getState($state): string
    {
        $state['check'] = $this->getCheckString();
        $state['adapter'] = $this->getAdapterBasename();
        $state['page'] = str_replace('index.php', '', $this->request->getRequestedPage());

        $arState = [];
        foreach ($state as $key => $value) {
            $arState[] = $key . '=' . $value;
        }

        return implode('&', $arState);
    }

    /**
     * @return array
     */
    private function parseState(): array
    {
        $arResult = [];

        foreach (explode('&', $this->request['state']) as $val) {
            $exp = explode('=', $val);
            $arResult[$exp[0]] = $exp[1];
        }

        return $arResult;
    }

    /**
     * Данным методом идентифицируется нужный адаптер
     *
     * @return bool
     */
    public function isCurrentRequest()
    {
        $parsed = $this->parseState();

        if ($parsed['check'] == $this->getCheckString() && $parsed['adapter'] == $this->getAdapterBasename()) {
            return true;
        }

        return false;
    }

    /**
     * Генерирует пароль при регистрации
     *
     * @return string
     */
    private function randomPassword()
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
        $pass = []; //remember to declare $pass as an array
        $alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
        for ($i = 0; $i < 8; $i++) {
            $n = rand(0, $alphaLength);
            $pass[] = $alphabet[$n];
        }
        return implode($pass); //turn the array into a string
    }

    /**
     * CURL-запрос
     *
     * @param $queryUrl
     * @param array $queryData
     * @param bool $post
     * @return mixed
     */
    protected function curl($queryUrl, array $queryData = [], bool $post = false)
    {
        $curl = curl_init();

        if ($post !== true) {
            if (strpos($queryUrl, '?') !== false && count($queryData)) {
                $queryUrl .= '&' . http_build_query($queryData);
            } else {
                if (count($queryData)) {
                    $queryUrl .= '?' . http_build_query($queryData);
                }
            }
        } else {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $queryData);
        }

        curl_setopt_array($curl, [
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL => $queryUrl
        ]);

        $result = curl_exec($curl);
        curl_close($curl);

        return $result;
    }
}
