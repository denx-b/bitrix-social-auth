<?

namespace Dbogdanoff\Bitrix\Auth;

/**
 * Class Auth
 * @package Bitrix Social Auth
 * @author Denis Bogdanov <info@dbogdanoff.ru>
 */
class Auth
{
    /**
     * Массив добавленных адаптеров.
     *
     * @var array
     */
    private static $adapters = [];

    /**
     * При добавлении первого адаптера присваивается значение true.
     *
     * @var bool
     */
    private static $init = false;

    /**
     * Добавление адаптера.
     *
     * @param Adapter\Adapter $adapter
     */
    public static function addAdapter(Adapter\Adapter $adapter)
    {
        if (self::$init !== true) {
            self::$init = true;
            \AddEventHandler('main', 'OnBeforeProlog', ['\Dbogdanoff\Bitrix\Auth\Auth', 'launch']);
        }

        self::$adapters[$adapter::ID] = $adapter;
    }

    /**
     * Возвращает массив с адаптерами.
     *
     * @return array
     */
    public static function getAdapters(): array
    {
        return self::$adapters;
    }

    /**
     * Идентификация и вызов адаптера.
     * После разрешения пользователем авторизации на стороне соц. сети
     * пользователь переадресуется обратно на сайт и в параметре state находятся данные,
     * которые позволяют помочь методу Adapter\Adapter::isCurrentRequest() понять какой используется адаптер
     * и запустить процедуру авторизации/регистрации Adapter\Adapter::oauth()
     */
    public static function launch()
    {
        foreach (self::$adapters as $adapter) {
            /** @var Adapter\Adapter $adapter */
            if ($adapter->isCurrentRequest()) {
                try {
                    $adapter->oauth();
                } catch (\Exception $e) {
                    echo '<div class="adapter-error">' . $e->getMessage() . '</div>';
                }
            }
        }
    }
}
