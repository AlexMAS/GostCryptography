namespace GostCryptography.Native
{
	/// <summary>
	/// Константы для работы с криптографическим провайдером.
	/// </summary>
	public static class Constants
	{
		// ReSharper disable InconsistentNaming


		#region Идентификаторы криптографических алгоритмов ГОСТ

		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2001.
		/// </summary>
		public const int CALG_DH_EL_SF = 0xaa24;

		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
		/// </summary>
		public const int CALG_DH_GR3410_2012_256_SF = 0xaa46;

		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
		/// </summary>
		public const int CALG_DH_GR3410_2012_512_SF = 0xaa42;


		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2001.
		/// </summary>
		public const int CALG_DH_EL_EPHEM = 0xaa25;

		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
		/// </summary>
		public const int CALG_DH_GR3410_12_256_EPHEM = 0xaa47;

		/// <summary>
		/// Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
		/// </summary>
		public const int CALG_DH_GR3410_12_512_EPHEM = 0xaa43;


		/// <summary>
		/// Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2001.
		/// </summary>
		public const int CALG_GR3410EL = 0x2e23;

		/// <summary>
		/// Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).
		/// </summary>
		public const int CALG_GR3410_2012_256 = 0x2e49;

		/// <summary>
		/// Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).
		/// </summary>
		public const int CALG_GR3410_2012_512 = 0x2e3d;


		/// <summary>
		/// Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
		/// </summary>
		public const int CALG_GR3411 = 0x801e;

		/// <summary>
		/// Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
		/// </summary>
		public const int CALG_GR3411_2012_256 = 0x8021;

		/// <summary>
		/// Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
		/// </summary>
		public const int CALG_GR3411_2012_512 = 0x8022;


		/// <summary>
		/// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>.
		/// </summary>
		public const int CALG_GR3411_HMAC = 0x8027;

		/// <summary>
		/// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 256 бит.
		/// </summary>
		public const int CALG_GR3411_2012_256_HMAC = 0x8034;

		/// <summary>
		/// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 512 бит.
		/// </summary>
		public const int CALG_GR3411_2012_512_HMAC = 0x8035;

		/// <summary>
		/// Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
		/// </summary>
		public const int CALG_GR3411_HMAC34 = 0x8028;


		/// <summary>
		/// Идентификатор алгоритма симметричного шифрования по ГОСТ 28147-89.
		/// </summary>
		public const int CALG_G28147 = 0x661e;

		/// <summary>
		/// Идентификатор алгоритма вычисления имитовставки по ГОСТ 28147-89.
		/// </summary>
		public const int CALG_G28147_IMIT = 0x801f;


		/// <summary>
		/// Идентификатор алгоритма экспорта ключа КриптоПро.
		/// </summary>
		public const int CALG_PRO_EXPORT = 0x661f;

		/// <summary>
		/// Идентификатор алгоритма экспорта ключа по ГОСТ 28147-89.
		/// </summary>
		public const int CALG_SIMPLE_EXPORT = 0x6620;

		#endregion


		#region Настройки контекста криптографического провайдера

		/// <summary>
		/// Создать новый ключевой контейнер.
		/// </summary>
		public const uint CRYPT_NEWKEYSET = 8;

		/// <summary>
		/// Использовать ключи локальной машины.
		/// </summary>
		public const uint CRYPT_MACHINE_KEYSET = 0x20;

		/// <summary>
		/// Получить доступ к провайдеру без необходимости доступа к приватным ключам.
		/// </summary>
		public const uint CRYPT_VERIFYCONTEXT = 0xf0000000;


		#endregion


		#region Параметры криптографического провайдера

		public const int PP_CLIENT_HWND = 1;

		/// <summary>
		/// Удаляет текущий контейнер с носителя.
		/// </summary>
		public const int PP_DELETE_KEYSET = 0x7d;

		/// <summary>
		/// Задаёт пароль (PIN) для доступа к ключу AT_KEYEXCHANGE.
		/// </summary>
		public const int PP_KEYEXCHANGE_PIN = 0x20;

		/// <summary>
		/// Задаёт пароль (PIN) для доступа к ключу AT_SIGNATURE.
		/// </summary>
		public const int PP_SIGNATURE_PIN = 0x21;

		/// <summary>
		/// Тип криптопровайдера.
		/// </summary>
		public const int PP_PROVTYPE = 0x10;

		#endregion


		#region Параметры функции хэширования криптографического провайдера

		/// <summary>
		/// Стартовый вектор функции хэширования, устанавливаемый приложением.
		/// </summary>
		public const int HP_HASHSTARTVECT = 8;

		/// <summary>
		/// Значение функции хэширования в little-endian порядке байт в соотвествии с типом GostR3411-94-Digest CPCMS [RFC 4490].
		/// </summary>
		public const int HP_HASHVAL = 2;

		#endregion


		#region Параметры функций шифрования криптографического провайдера

		/// <summary>
		/// Признак ключей ГОСТ 28147-89 и мастер ключей TLS.
		/// </summary>
		public const int G28147_MAGIC = 0x374A51FD;

		/// <summary>
		/// Признак ключей ГОСТ Р 34.10-94 и ГОСТ Р 34.10-2001.
		/// </summary>
		public const int GR3410_1_MAGIC = 0x3147414D;

		#endregion


		#region Параметры транспортировки ключей

		/// <summary>
		/// Используется для транспортировки симметричных ключей CALG_G28147, CALG_UECSYMMETRIC.
		/// </summary>
		public const int SIMPLEBLOB = 1;

		/// <summary>
		/// Используется для транспортировки открытых ключей.
		/// </summary>
		public const int PUBLICKEYBLOB = 6;

		#endregion


		#region Параметры ключей криптографического провайдера

		/// <summary>
		/// Вектор инициализации (IV, синхропосылки) алгоритма шифрования.
		/// </summary>
		public const int KP_IV = 1;

		/// <summary>
		/// Метод дополнения шифра ключа.
		/// </summary>
		public const int KP_PADDING = 3;

		/// <summary>
		/// Режим шифра ключа.
		/// </summary>
		public const int KP_MODE = 4;

		/// <summary>
		/// Идентификатор алгоритма ключа.
		/// </summary>
		public const int KP_ALGID = 7;

		/// <summary>
		/// Идентификатор алгоритма экспорта для симметричного ключа.
		/// </summary>
		public const int KP_EXPORTID = 108;

		/// <summary>
		/// Строковый идентификатор узла замены.
		/// </summary>
		public const int KP_CIPHEROID = 0x68;

		/// <summary>
		/// Строковый идентификатор параметров ключа ГОСТ Р 34.10-2001, применяемых в алгоритме Диффи-Хеллмана.
		/// </summary>
		public const int KP_DHOID = 0x6a;

		/// <summary>
		/// Строковый идентификатор функции хэширования.
		/// </summary>
		public const int KP_HASHOID = 0x67;

		/// <summary>
		/// Закрытый ключ в ключевой паре.
		/// </summary>
		public const int KP_X = 14;

		/// <summary>
		/// Произведенный ключ может быть передан из криптопровайдера в ключевой блоб при экспорте ключа независимо от сессии криптопровайдера (исключает CRYPT_ARCHIVABLE).
		/// </summary>
		public const int CRYPT_EXPORTABLE = 1;

		/// <summary>
		/// Произведенный ключ может быть передан из криптопровайдера в ключевой блоб при экспорте ключа в раках одной сессии криптопровайдера (исключает CRYPT_EXPORTABLE).
		/// </summary>
		public const int CRYPT_ARCHIVABLE = 0x4000;

		/// <summary>
		/// При любом запросе на доступ к носителю закрытого ключа пользователя выводится окно диалога, запрашивающего право доступа к ключу.
		/// </summary>
		public const int CRYPT_USER_PROTECTED = 2;

		/// <summary>
		/// Генерация пустой ключевой пары обмена.
		/// </summary>
		public const int CRYPT_PREGEN = 0x40;

		/// <summary>
		/// Пара ключей для обмена ключами.
		/// </summary>
		public const int AT_KEYEXCHANGE = 1;

		/// <summary>
		/// Пара ключей для формирования цифровой подписи
		/// </summary>
		public const int AT_SIGNATURE = 2;

		#endregion


		#region Методы дополнения шифра ключа (KP_PADDING)

		/// <summary>
		/// PKCS#5.
		/// </summary>
		public const int PKCS5_PADDING = 1;

		/// <summary>
		/// Дополнение случайными байтами.
		/// </summary>
		public const int RANDOM_PADDING = 2;

		/// <summary>
		/// Дополнение нулевыми байтами.
		/// </summary>
		public const int ZERO_PADDING = 3;

		#endregion


		#region Режимы шифра ключа (KP_MODE)

		/// <summary>
		/// Cipher Block Chaining (CBC).
		/// </summary>
		public const int CRYPT_MODE_CBC = 1;

		/// <summary>
		/// Electronic codebook (ECB).
		/// </summary>
		public const int CRYPT_MODE_ECB = 2;

		/// <summary>
		/// Output Feedback (OFB).
		/// </summary>
		public const int CRYPT_MODE_OFB = 3;

		/// <summary>
		/// Cipher Feedback (CFB).
		/// </summary>
		public const int CRYPT_MODE_CFB = 4;

		/// <summary>
		/// Ciphertext stealing (CTS).
		/// </summary>
		public const int CRYPT_MODE_CTS = 5;

		#endregion


		#region Коды ошибок

		/// <summary>
		/// Aлгоритм, который данный криптопровайдер не поддерживает.
		/// </summary>
		public const int NTE_BAD_ALGID = -2146893816;

		/// <summary>
		/// Данные некорректного размера.
		/// </summary>
		public const int NTE_BAD_DATA = -2146893819;

		/// <summary>
		/// Дескриптор хэша ошибочен.
		/// </summary>
		public const int NTE_BAD_HASH = -2146893822;

		/// <summary>
		/// Ключевой контейнер не был открыт или не существует.
		/// </summary>
		public const int NTE_BAD_KEYSET = -2146893802;

		/// <summary>
		/// Ключевой контейнер с заданным именем не существует.
		/// </summary>
		public const int NTE_KEYSET_NOT_DEF = -2146893799;

		/// <summary>
		/// Ключ с заданным параметром (AT_KEYEXCHANGE, AT_SIGNATURE или AT_UECSYMMETRICKEY) не существует.
		/// </summary>
		public const int NTE_NO_KEY = -2146893811;

		/// <summary>
		/// Пользователь прервал операцию.
		/// </summary>
		public const int SCARD_W_CANCELLED_BY_USER = -2146434962;

		#endregion


		// ReSharper restore InconsistentNaming
	}
}