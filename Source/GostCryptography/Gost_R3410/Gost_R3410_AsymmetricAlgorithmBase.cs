using System.Security;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма ГОСТ Р 34.10.
	/// </summary>
	/// <typeparam name="TKeyParams">Параметры ключа цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyAlgorithm">Алгоритм общего секретного ключа ГОСТ Р 34.10.</typeparam>
	public abstract class Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> : GostAsymmetricAlgorithm
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		/// <inheritdoc cref="GostAsymmetricAlgorithm(ProviderType,int)" />
		protected Gost_R3410_AsymmetricAlgorithmBase(ProviderType providerType, int keySize) : base(providerType, keySize)
		{
		}


		/// <summary>
		/// Идентификатор алгоритма обмена ключей.
		/// </summary>
		protected abstract int ExchangeAlgId { get; }
		/// <summary>
		/// Идентификатор алгоритма цифровой подписи.
		/// </summary>
		protected abstract int SignatureAlgId { get; }


		/// <summary>
		/// Создает экземпляр <typeparamref name="TKeyParams"/>.
		/// </summary>
		protected abstract TKeyParams CreateKeyExchangeParams();

		/// <summary>
		/// Создает экземпляр <typeparamref name="TKeyAlgorithm"/>.
		/// </summary>
		[SecuritySafeCritical]
		protected abstract TKeyAlgorithm CreateKeyExchangeAlgorithm(ProviderType providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, TKeyParams keyExchangeParameters);

		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		public abstract TKeyAlgorithm CreateKeyExchange(TKeyParams keyParameters);


		/// <summary>
		/// Экспортирует (шифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		public abstract TKeyParams ExportParameters(bool includePrivateKey);

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		public abstract void ImportParameters(TKeyParams keyParameters);

		/// <summary>
		/// Создает XML-сериализатор параметров ключа цифровой подписи.
		/// </summary>
		protected abstract Gost_R3410_KeyExchangeXmlSerializer<TKeyParams> CreateKeyExchangeXmlSerializer();


		/// <inheritdoc />
		public override string ToXmlString(bool includePrivateKey)
		{
			var keyParameters = ExportParameters(includePrivateKey);
			var xmlSerializer = CreateKeyExchangeXmlSerializer();
			return xmlSerializer.Serialize(keyParameters);
		}

		/// <inheritdoc />
		public override void FromXmlString(string keyParametersXml)
		{
			var xmlSerializer = CreateKeyExchangeXmlSerializer();
			var keyParameters = xmlSerializer.Deserialize(keyParametersXml, CreateKeyExchangeParams());
			ImportParameters(keyParameters);
		}
	}
}