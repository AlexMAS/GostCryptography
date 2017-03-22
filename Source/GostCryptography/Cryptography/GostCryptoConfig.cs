using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
    /// <summary>
    /// Предоставляет методы для доступа к конфигурационной информации, используемой при работе с криптографическим провайдером ГОСТ.
    /// </summary>
    public static class GostCryptoConfig
    {
        /// <summary>
        /// Наименование алгоритма шифрования по умолчанию.
        /// </summary>
        public const string DefaultEncryptionName = "Gost28147";

        /// <summary>
        /// Идентификатор OID алгоритма шифрования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм симметричного шифрования по ГОСТ 28147-89.
        /// </remarks>
        public const string DefaultEncryptionOid = "1.2.643.2.2.21";


        /// <summary>
        /// Наименование алгоритма подписи по умолчанию.
        /// </summary>
        public const string DefaultSignName = "Gost3410";

        /// <summary>
        /// Идентификатор OID алгоритма подписи по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм подписи по ГОСТ Р 34.10.
        /// </remarks>
        public const string DefaultSignOid = "1.2.643.2.2.19";


        /// <summary>
        /// Наименование алгоритма хэширования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм хэширования по ГОСТ Р 34.11-94.
        /// </remarks>
        public const string DefaultHashName = Hash3411Name;

        /// <summary>
        /// Наименование алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
        /// </summary>
        public const string Hash3411Name = "Gost3411";

        /// <summary>
        /// Наименование алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
        /// </summary>
        public const string Hash34112012256Name = "Gost34112012256";

        /// <summary>
        /// Наименование алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
        /// </summary>
        public const string Hash34112012512Name = "Gost34112012512";


        /// <summary>
        /// Идентификатор OID алгоритма хэширования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм хэширования по ГОСТ Р 34.11-94.
        /// </remarks>
        public const string DefaultHashOid = Hash3411Oid;

        /// <summary>
        /// Идентификатор OID алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
        /// </summary>
        public const string Hash3411Oid = "1.2.643.2.2.9";

        /// <summary>
        /// Идентификатор OID алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
        /// </summary>
        public const string Hash34112012256Oid = "1.2.643.7.1.1.2.2";

        /// <summary>
        /// Идентификатор OID алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
        /// </summary>
        public const string Hash34112012512Oid = "1.2.643.7.1.1.2.3";


        /// <summary>
        /// Идентификатор XmlDsigName алгоритма хэширования по умолчанию.
        /// </summary>
        /// <remarks>
        /// Алгоритм хэширования по ГОСТ Р 34.11-94.
        /// </remarks>
        public const string DefaultHashXmlDsigName = Hash3411XmlDsigName;

        /// <summary>
        /// Идентификатор XmlDsigName алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
        /// </summary>
        public const string Hash3411XmlDsigName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

        /// <summary>
        /// Идентификатор XmlDsigName алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
        /// </summary>
        public const string Hash34112012256XmlDsigName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";

        /// <summary>
        /// Идентификатор XmlDsigName алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
        /// </summary>
        public const string Hash34112012512XmlDsigName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";


        /// <summary>
        /// Статический конструктор.
        /// </summary>
        static GostCryptoConfig()
        {
            ProviderType = ProviderTypes.VipNet;
            InitializeDefaultNameToTypes();
            InitializeDefaultNameToOid();
        }


        private static readonly Dictionary<string, Type> DefaultNameToTypes
            = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

        private static void InitializeDefaultNameToTypes()
        {
            // Информация о свойствах цифровой подписи ГОСТ Р 34.10-2001
            AddDefaultNamesToType<GostSignatureDescription>("http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411");

            // Реализация алгоритма подписи по ГОСТ Р 34.10
            AddDefaultNamesToType<Gost3410AsymmetricAlgorithm>(DefaultSignName);

            // Реализация алгоритма хэширования по ГОСТ Р 34.11
            AddDefaultNamesToType<Gost3411HashAlgorithm>(Hash3411Name, Hash3411XmlDsigName, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
            AddDefaultNamesToType<Gost34112012256HashAlgorithm>(Hash34112012256Name, Hash34112012256XmlDsigName);
            AddDefaultNamesToType<Gost34112012512HashAlgorithm>(Hash34112012512Name, Hash34112012512XmlDsigName);

            // Реализация алгоритма симметричного шифрования по ГОСТ 28147
            AddDefaultNamesToType<Gost28147SymmetricAlgorithm>(DefaultEncryptionName);

            // Реализация функции вычисления имитовставки по ГОСТ 28147
            AddDefaultNamesToType<Gost28147ImitHashAlgorithm>("Gost28147Imit");

            // Реализация HMAC на базе алгоритма хэширования по ГОСТ Р 34.11
            AddDefaultNamesToType<Gost3411Hmac>("urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr3411");

            // Реализация алгоритма генерации псевдослучайной последовательности по ГОСТ Р 34.11
            AddDefaultNamesToType<Gost3411Prf>();

            // Класс вычисления цифровой подписи по ГОСТ Р 34.10-2001
            AddDefaultNamesToType<GostSignatureFormatter>();

            // Класс проверки цифровой подписи по ГОСТ Р 34.10-2001
            AddDefaultNamesToType<GostSignatureDeformatter>();

            // Параметры ключа цифровой подписи ГОСТ Р 34.10
            AddDefaultNamesToType<GostKeyValue>("http://www.w3.org/2000/09/xmldsig# KeyValue/GostKeyValue");
        }

        [SecuritySafeCritical]
        public static void AddDefaultNamesToType<T>(params string[] names)
        {
            var type = typeof(T);

            if (names != null)
            {
                foreach (var name in names)
                {
                    DefaultNameToTypes.Add(name, type);
                    CryptoConfig.AddAlgorithm(type, name);
                }
            }

            DefaultNameToTypes.Add(type.Name, type);
            CryptoConfig.AddAlgorithm(type, type.Name);

            DefaultNameToTypes.Add(type.FullName, type);
            CryptoConfig.AddAlgorithm(type, type.FullName);

            if (type.AssemblyQualifiedName != null)
            {
                DefaultNameToTypes.Add(type.AssemblyQualifiedName, type);
                CryptoConfig.AddAlgorithm(type, type.AssemblyQualifiedName);
            }
        }


        private static readonly Dictionary<string, string> DefaultNameToOid
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private static void InitializeDefaultNameToOid()
        {
            // Реализация алгоритма подписи по ГОСТ Р 34.10
            AddDefaultNamesToOid<Gost3410AsymmetricAlgorithm>(DefaultSignOid, DefaultSignName);

            // Реализация алгоритма хэширования по ГОСТ Р 34.11
            AddDefaultNamesToOid<Gost3411HashAlgorithm>(Hash3411Oid, Hash3411Name, Hash3411XmlDsigName, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
            AddDefaultNamesToOid<Gost34112012256HashAlgorithm>(Hash34112012256Oid, Hash34112012256Name, Hash34112012256XmlDsigName);
            AddDefaultNamesToOid<Gost34112012512HashAlgorithm>(Hash34112012512Oid, Hash34112012512Name, Hash34112012512XmlDsigName);

            // Реализация алгоритма симметричного шифрования по ГОСТ 28147
            AddDefaultNamesToOid<Gost28147SymmetricAlgorithm>(DefaultEncryptionOid, DefaultEncryptionName);
        }

        [SecuritySafeCritical]
        public static void AddDefaultNamesToOid<T>(string oid, params string[] names)
        {
            var type = typeof(T);

            if (names != null)
            {
                foreach (var name in names)
                {
                    DefaultNameToOid.Add(name, oid);
                    CryptoConfig.AddOID(oid, name);
                }
            }

            DefaultNameToOid.Add(type.Name, oid);
            CryptoConfig.AddOID(oid, type.Name);

            DefaultNameToOid.Add(type.FullName, oid);
            CryptoConfig.AddOID(oid, type.FullName);

            if (type.AssemblyQualifiedName != null)
            {
                DefaultNameToOid.Add(type.AssemblyQualifiedName, oid);
                CryptoConfig.AddOID(oid, type.AssemblyQualifiedName);
            }
        }


        /// <summary>
        /// Идентификатор типа криптографического провайдера.
        /// </summary>
        public static int ProviderType { get; set; }


        public static void Initialize()
        {
            // На самом деле инициализация происходит в статическом конструкторе
        }

        public static string MapNameToOid(string name)
        {
            string oid = null;

            if (!string.IsNullOrEmpty(name))
            {
                oid = CryptoConfig.MapNameToOID(name);

                if (string.IsNullOrEmpty(oid))
                {
                    DefaultNameToOid.TryGetValue(name, out oid);
                }
            }

            return oid;
        }

        public static object CreateFromName(string name, params object[] arguments)
        {
            object obj = null;

            if (!string.IsNullOrEmpty(name))
            {
                obj = CryptoConfig.CreateFromName(name, arguments);

                if (obj == null)
                {
                    Type objType;

                    if (DefaultNameToTypes.TryGetValue(name, out objType))
                    {
                        obj = Activator.CreateInstance(objType, arguments);
                    }
                }
            }

            return obj;
        }
    }
}