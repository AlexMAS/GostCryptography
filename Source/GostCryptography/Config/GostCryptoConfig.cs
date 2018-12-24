using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Asn1.Gost.Gost_R3410_94;
using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Gost_R3410;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;
using GostCryptography.Xml;

namespace GostCryptography.Config
{
	/// <summary>
	/// Предоставляет методы для доступа к конфигурационной информации, используемой при работе с криптографическим провайдером ГОСТ.
	/// </summary>
	public static class GostCryptoConfig
	{
		private static Lazy<ProviderType> _providerType_2001;
		private static Lazy<ProviderType> _providerType_2012_512;
		private static Lazy<ProviderType> _providerType_2012_1024;
		private static readonly Dictionary<string, Type> NameToType = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);
		private static readonly Dictionary<string, string> NameToOid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);


		static GostCryptoConfig()
		{
			InitDefaultProviders();
			AddKnownAlgorithms();
			AddKnownOIDs();
		}

		[SecuritySafeCritical]
		private static void InitDefaultProviders()
		{
			_providerType_2001 = new Lazy<ProviderType>(CryptoApiHelper.GetAvailableProviderType_2001);
			_providerType_2012_512 = new Lazy<ProviderType>(CryptoApiHelper.GetAvailableProviderType_2012_512);
			_providerType_2012_1024 = new Lazy<ProviderType>(CryptoApiHelper.GetAvailableProviderType_2012_1024);
		}

		private static void AddKnownAlgorithms()
		{
			AddAlgorithm<Gost_R3410_2001_SignatureDescription>(Gost_R3410_2001_AsymmetricAlgorithm.KnownSignatureAlgorithmNames);
			AddAlgorithm<Gost_R3410_2012_256_SignatureDescription>(Gost_R3410_2012_256_AsymmetricAlgorithm.KnownSignatureAlgorithmNames);
			AddAlgorithm<Gost_R3410_2012_512_SignatureDescription>(Gost_R3410_2012_512_AsymmetricAlgorithm.KnownSignatureAlgorithmNames);

			AddAlgorithm<Gost_R3411_94_HashAlgorithm>(Gost_R3411_94_HashAlgorithm.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_256_HashAlgorithm>(Gost_R3411_2012_256_HashAlgorithm.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_512_HashAlgorithm>(Gost_R3411_2012_512_HashAlgorithm.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_94_HMAC>(Gost_R3411_94_HMAC.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_256_HMAC>(Gost_R3411_2012_256_HMAC.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_512_HMAC>(Gost_R3411_2012_512_HMAC.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_94_PRF>(Gost_R3411_94_PRF.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_256_PRF>(Gost_R3411_2012_256_PRF.KnownAlgorithmNames);
			AddAlgorithm<Gost_R3411_2012_512_PRF>(Gost_R3411_2012_512_PRF.KnownAlgorithmNames);

			AddAlgorithm<Gost_28147_89_SymmetricAlgorithm>(Gost_28147_89_SymmetricAlgorithm.KnownAlgorithmNames);
			AddAlgorithm<Gost_28147_89_ImitHashAlgorithm>(Gost_28147_89_ImitHashAlgorithm.KnownAlgorithmNames);

			AddAlgorithm<Gost_R3410_2001_AsymmetricAlgorithm>();
			AddAlgorithm<Gost_R3410_2012_256_AsymmetricAlgorithm>();
			AddAlgorithm<Gost_R3410_2012_512_AsymmetricAlgorithm>();

			AddAlgorithm<GostSignatureFormatter>();
			AddAlgorithm<GostSignatureDeformatter>();

			AddAlgorithm<Gost_R3410_2001_KeyValue>(Gost_R3410_2001_KeyValue.KnownValueUrls);
			AddAlgorithm<Gost_R3410_2012_256_KeyValue>(Gost_R3410_2012_256_KeyValue.KnownValueUrls);
			AddAlgorithm<Gost_R3410_2012_512_KeyValue>(Gost_R3410_2012_512_KeyValue.KnownValueUrls);
		}

		private static void AddKnownOIDs()
		{
			AddOID<Gost_R3410_2001_AsymmetricAlgorithm>(Gost_R3410_2001_Constants.KeyAlgorithm.Value);
			AddOID<Gost_R3410_2012_256_AsymmetricAlgorithm>(Gost_R3410_2012_256_Constants.KeyAlgorithm.Value);
			AddOID<Gost_R3410_2012_512_AsymmetricAlgorithm>(Gost_R3410_2012_512_Constants.KeyAlgorithm.Value);

			AddOID<Gost_R3411_94_HashAlgorithm>(Gost_R3410_94_Constants.HashAlgorithm.Value, Gost_R3411_94_HashAlgorithm.KnownAlgorithmNames);
			AddOID<Gost_R3411_2012_256_HashAlgorithm>(Gost_R3410_2012_256_Constants.HashAlgorithm.Value, Gost_R3411_2012_256_HashAlgorithm.KnownAlgorithmNames);
			AddOID<Gost_R3411_2012_512_HashAlgorithm>(Gost_R3410_2012_512_Constants.HashAlgorithm.Value, Gost_R3411_2012_512_HashAlgorithm.KnownAlgorithmNames);

			AddOID<Gost_28147_89_SymmetricAlgorithm>(Gost_28147_89_Constants.EncryptAlgorithm.Value, Gost_28147_89_SymmetricAlgorithm.KnownAlgorithmNames);
		}


		/// <summary>
		/// Инициализирует конфигурацию.
		/// </summary>
		public static void Initialize()
		{
			// На самом деле инициализация происходит в статическом конструкторе
		}


		/// <summary>
		/// Возвращает провайдер по умолчанию для ключей ГОСТ Р 34.10-2001.
		/// </summary>
		public static ProviderType ProviderType => _providerType_2001.Value;

		/// <summary>
		/// Возвращает провайдер по умолчанию для ключей ГОСТ Р 34.10-2012/512.
		/// </summary>
		public static ProviderType ProviderType_2012_512 => _providerType_2012_512.Value;

		/// <summary>
		/// Возвращает провайдер по умолчанию для ключей ГОСТ Р 34.10-2012/1024.
		/// </summary>
		public static ProviderType ProviderType_2012_1024 => _providerType_2012_1024.Value;


		/// <summary>
		/// Добавляет связь между алгоритмом и именем.
		/// </summary>
		[SecuritySafeCritical]
		public static void AddAlgorithm<T>(params string[] names)
		{
			var type = typeof(T);

			if (names != null)
			{
				foreach (var name in names)
				{
					NameToType.Add(name, type);
					CryptoConfig.AddAlgorithm(type, name);
				}
			}

			NameToType.Add(type.Name, type);
			CryptoConfig.AddAlgorithm(type, type.Name);

			if (type.FullName != null)
			{
				NameToType.Add(type.FullName, type);
				CryptoConfig.AddAlgorithm(type, type.FullName);
			}

			if (type.AssemblyQualifiedName != null)
			{
				NameToType.Add(type.AssemblyQualifiedName, type);
				CryptoConfig.AddAlgorithm(type, type.AssemblyQualifiedName);
			}
		}

		/// <summary>
		/// Добавляет связь между алгоритмом и OID.
		/// </summary>
		[SecuritySafeCritical]
		public static void AddOID<T>(string oid, params string[] names)
		{
			var type = typeof(T);

			if (names != null)
			{
				foreach (var name in names)
				{
					NameToOid.Add(name, oid);
					CryptoConfig.AddOID(oid, name);
				}
			}

			NameToOid.Add(type.Name, oid);
			CryptoConfig.AddOID(oid, type.Name);

			if (type.FullName != null)
			{
				NameToOid.Add(type.FullName, oid);
				CryptoConfig.AddOID(oid, type.FullName);
			}

			if (type.AssemblyQualifiedName != null)
			{
				NameToOid.Add(type.AssemblyQualifiedName, oid);
				CryptoConfig.AddOID(oid, type.AssemblyQualifiedName);
			}
		}

		/// <inheritdoc cref="CryptoConfig.MapNameToOID"/>
		public static string MapNameToOID(string name)
		{
			string oid = null;

			if (!string.IsNullOrEmpty(name))
			{
				oid = CryptoConfig.MapNameToOID(name);

				if (string.IsNullOrEmpty(oid))
				{
					NameToOid.TryGetValue(name, out oid);
				}
			}

			return oid;
		}

		/// <inheritdoc cref="CryptoConfig.CreateFromName(string,object[])"/>
		public static object CreateFromName(string name, params object[] arguments)
		{
			object obj = null;

			if (!string.IsNullOrEmpty(name))
			{
				obj = CryptoConfig.CreateFromName(name, arguments);

				if (obj == null && NameToType.TryGetValue(name, out var objType))
				{
					obj = Activator.CreateInstance(objType, arguments);
				}
			}

			return obj;
		}
	}
}