## Bitrix Social Auth

init.php:
```php
use Dbogdanoff\Bitrix\Auth\Auth;
use Dbogdanoff\Bitrix\Auth\Adapter;

try {
    Auth::addAdapter(new Adapter\Vk([
        'client_id' => '123456',
        'client_secret' => 'xxxxxxxxxx'
    ]));
    Auth::addAdapter(new Adapter\Fb([
        'client_id' => '123456',
        'client_secret' => 'xxxxxxxxxx'
    ]));
    Auth::addAdapter(new Adapter\Google([
        'client_id' => '123456',
        'client_secret' => 'xxxxxxxxxx'
    ]));
}
catch (\Exception $e) {
    echo '<div class="adapter-error">' . $e->getMessage() . '</div>';
}
```

Вариант публичной части:
```php
<ul class="auth__list">
  <?$adapters = \Dbogdanoff\Bitrix\Auth\Auth::getAdapters();?>
  <li class="auth__item">
    <a class="auth__link" href="<?=$adapters['Facebook']->getAuthUrl()?>">
      <svg class="auth__icon" width="20" height="20">
        <use xlink:href="#facebook"></use>
      </svg>
    </a>
  </li>
  <li class="auth__item">
    <a class="auth__link" href="<?=$adapters['VKontakte']->getAuthUrl()?>">
      <svg class="auth__icon" width="22" height="22">
        <use xlink:href="#vk"></use>
      </svg>
    </a>
  </li>
  ...
</ul>
```

## Requirements

Bitrix Social Auth requires the following:

- PHP 7.0.0+
- [1C-Bitrix 14.0.0+](https://www.1c-bitrix.ru/)

## Installation

Bitrix Social Auth is installed via [Composer](https://getcomposer.org/).
To [add a dependency](https://getcomposer.org/doc/04-schema.md#package-links>) to bitrix-social-auth in your project, either

Run the following to use the latest stable version
```sh
    composer require denx-b/bitrix-social-auth
```
or if you want the latest master version
```sh
    composer require denx-b/bitrix-social-auth:dev-master
```

You can of course also manually edit your composer.json file
```json
{
    "require": {
       "denx-b/bitrix-social-auth": "0.*"
    }
}
```

## Свои адаптеры

Для создания нового адаптера необходимо создать класс и наследовать его от абстрактного класса [\Dbogdanoff\Bitrix\Auth\Adapter\Adapter](https://github.com/denx-b/bitrix-social-auth/blob/master/src/Bitrix/Auth/Adapter/Adapter.php)

Класс имеет 4 абстрактных метода, которые необходимо реализовать и 3 вспомогательные константы:
```php
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
```

Это собственно и всё, что потребуется для создания новых адаптеров. \
Для наглядности можно посмотреть [пример](https://github.com/denx-b/bitrix-social-auth/blob/master/src/Bitrix/Auth/Adapter/Google.php) уже созданного адаптера.\
Буду всеми рукам за, если вы предложите новые адаптеры для других соц. сетей.
